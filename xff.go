package clientip

import (
	"net/netip"
	"strings"
)

// typicalChainCapacity is the initial capacity used when parsing proxy chains.
//
// Most deployments have short chains (around 1-5 hops). Preallocating 8 avoids
// reallocations in common cases without meaningful memory overhead.
const typicalChainCapacity = 8

func (e *Extractor) isTrustedProxy(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if e.config.trustedProxyMatch.initialized {
		return e.config.trustedProxyMatch.contains(ip)
	}

	for _, cidr := range e.config.trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func (e *Extractor) validateProxyCount(trustedCount int) error {
	if len(e.config.trustedProxyCIDRs) > 0 && e.config.minTrustedProxies > 0 && trustedCount == 0 {
		e.config.metrics.RecordSecurityEvent(securityEventNoTrustedProxies)
		return ErrNoTrustedProxies
	}

	if e.config.minTrustedProxies > 0 && trustedCount < e.config.minTrustedProxies {
		e.config.metrics.RecordSecurityEvent(securityEventTooFewTrustedProxies)
		return ErrTooFewTrustedProxies
	}

	if e.config.maxTrustedProxies > 0 && trustedCount > e.config.maxTrustedProxies {
		e.config.metrics.RecordSecurityEvent(securityEventTooManyTrustedProxies)
		return ErrTooManyTrustedProxies
	}

	return nil
}

func (e *Extractor) parseXFFValues(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	parts := make([]string, 0, typicalChainCapacity)
	for _, v := range values {
		for part := range strings.SplitSeq(v, ",") {
			if trimmed := strings.TrimSpace(part); trimmed != "" {
				var err error
				parts, err = e.appendChainPart(parts, trimmed, SourceXForwardedFor)
				if err != nil {
					return nil, err
				}
			}
		}
	}
	return parts, nil
}

// appendChainPart appends one parsed chain part while enforcing maxChainLength.
func (e *Extractor) appendChainPart(parts []string, part, sourceName string) ([]string, error) {
	if len(parts) >= e.config.maxChainLength {
		e.config.metrics.RecordSecurityEvent(securityEventChainTooLong)
		return nil, &ChainTooLongError{
			ExtractionError: ExtractionError{
				Err:    ErrChainTooLong,
				Source: sourceName,
			},
			ChainLength: len(parts) + 1,
			MaxLength:   e.config.maxChainLength,
		}
	}

	return append(parts, part), nil
}

type chainAnalysis struct {
	clientIndex    int
	trustedCount   int
	trustedIndices []int
}

func (e *Extractor) clientIPFromChainWithDebug(sourceName string, parts []string) (netip.Addr, int, *ChainDebugInfo, error) {
	if len(parts) == 0 {
		return netip.Addr{}, 0, nil, &ExtractionError{
			Err:    ErrInvalidIP,
			Source: sourceName,
		}
	}

	analysis, clientIP, err := e.analyzeChainForExtraction(parts, e.config.debugMode)

	var debugInfo *ChainDebugInfo
	if e.config.debugMode {
		debugInfo = &ChainDebugInfo{
			FullChain:      parts,
			ClientIndex:    analysis.clientIndex,
			TrustedIndices: analysis.trustedIndices,
		}
	}

	if err != nil {
		chain := strings.Join(parts, ", ")
		return netip.Addr{}, analysis.trustedCount, debugInfo, &ProxyValidationError{
			ExtractionError: ExtractionError{
				Err:    err,
				Source: sourceName,
			},
			Chain:             chain,
			TrustedProxyCount: analysis.trustedCount,
			MinTrustedProxies: e.config.minTrustedProxies,
			MaxTrustedProxies: e.config.maxTrustedProxies,
		}
	}

	clientIPStr := parts[analysis.clientIndex]

	if !e.isPlausibleClientIP(clientIP) {
		chain := strings.Join(parts, ", ")
		return netip.Addr{}, analysis.trustedCount, debugInfo, &InvalidIPError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: sourceName,
			},
			Chain:          chain,
			ExtractedIP:    clientIPStr,
			Index:          analysis.clientIndex,
			TrustedProxies: analysis.trustedCount,
		}
	}

	return normalizeIP(clientIP), analysis.trustedCount, debugInfo, nil
}

func (e *Extractor) analyzeChainForExtraction(parts []string, collectTrustedIndices bool) (chainAnalysis, netip.Addr, error) {
	if len(parts) == 0 {
		return chainAnalysis{}, netip.Addr{}, nil
	}

	if e.config.chainSelection == LeftmostUntrustedIP {
		return e.analyzeChainLeftmostForExtraction(parts, collectTrustedIndices)
	}
	return e.analyzeChainRightmostForExtraction(parts, collectTrustedIndices)
}

func (e *Extractor) analyzeChainRightmost(parts []string) (chainAnalysis, error) {
	analysis, _, err := e.analyzeChainRightmostForExtraction(parts, true)
	return analysis, err
}

func (e *Extractor) analyzeChainRightmostForExtraction(parts []string, collectTrustedIndices bool) (chainAnalysis, netip.Addr, error) {
	trustedCount := 0
	clientIndex := 0
	clientIP := netip.Addr{}

	var trustedIndices []int
	if collectTrustedIndices {
		trustedIndices = make([]int, 0, len(parts))
	}

	hasCIDRs := len(e.config.trustedProxyCIDRs) > 0

	for i := len(parts) - 1; i >= 0; i-- {
		if !hasCIDRs && e.config.maxTrustedProxies > 0 && trustedCount >= e.config.maxTrustedProxies {
			clientIndex = i
			clientIP = parseIP(parts[i])
			break
		}

		ip := parseIP(parts[i])

		if hasCIDRs && !e.isTrustedProxy(ip) {
			clientIndex = i
			clientIP = ip
			break
		}

		if collectTrustedIndices {
			trustedIndices = append(trustedIndices, i)
		}
		trustedCount++
		clientIP = ip
	}

	analysis := chainAnalysis{
		clientIndex:    clientIndex,
		trustedCount:   trustedCount,
		trustedIndices: trustedIndices,
	}

	if err := e.validateProxyCount(trustedCount); err != nil {
		return analysis, netip.Addr{}, err
	}

	return analysis, clientIP, nil
}

func (e *Extractor) analyzeChainLeftmost(parts []string) (chainAnalysis, error) {
	analysis, _, err := e.analyzeChainLeftmostForExtraction(parts, true)
	return analysis, err
}

func (e *Extractor) analyzeChainLeftmostForExtraction(parts []string, collectTrustedIndices bool) (chainAnalysis, netip.Addr, error) {
	if len(e.config.trustedProxyCIDRs) == 0 {
		analysis := chainAnalysis{clientIndex: 0, trustedCount: 0}
		return analysis, parseIP(parts[0]), nil
	}

	trustedCount := 0
	trustedFlags := make([]bool, len(parts))

	var trustedIndices []int
	if collectTrustedIndices {
		trustedIndices = make([]int, 0, len(parts))
	}

	stillTrailingTrusted := true

	for i := len(parts) - 1; i >= 0; i-- {
		isTrusted := e.isTrustedProxy(parseIP(parts[i]))
		trustedFlags[i] = isTrusted

		if stillTrailingTrusted && isTrusted {
			if collectTrustedIndices {
				trustedIndices = append(trustedIndices, i)
			}
			trustedCount++
			continue
		}

		stillTrailingTrusted = false
	}

	analysis := chainAnalysis{
		trustedCount:   trustedCount,
		trustedIndices: trustedIndices,
	}

	if err := e.validateProxyCount(trustedCount); err != nil {
		return analysis, netip.Addr{}, err
	}

	analysis.clientIndex = selectLeftmostUntrustedTrusted(trustedFlags, trustedCount)
	return analysis, parseIP(parts[analysis.clientIndex]), nil
}

func (e *Extractor) selectLeftmostUntrustedIP(parts []string, trustedProxiesFromRight int) int {
	trustedFlags := make([]bool, len(parts))
	for i, part := range parts {
		trustedFlags[i] = e.isTrustedProxy(parseIP(part))
	}

	return selectLeftmostUntrustedTrusted(trustedFlags, trustedProxiesFromRight)
}

func selectLeftmostUntrustedTrusted(trustedFlags []bool, trustedProxiesFromRight int) int {
	untrustedPortionEnd := max(len(trustedFlags)-trustedProxiesFromRight, 0)

	for i := range untrustedPortionEnd {
		if !trustedFlags[i] {
			return i
		}
	}

	return max(untrustedPortionEnd-1, 0)
}

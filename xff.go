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

	analysis, err := e.analyzeChain(parts)

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
	clientIP := parseIP(clientIPStr)

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

func (e *Extractor) analyzeChain(parts []string) (chainAnalysis, error) {
	if len(parts) == 0 {
		return chainAnalysis{}, nil
	}

	if e.config.chainSelection == LeftmostUntrustedIP {
		return e.analyzeChainLeftmost(parts)
	}
	return e.analyzeChainRightmost(parts)
}

func (e *Extractor) analyzeChainRightmost(parts []string) (chainAnalysis, error) {
	trustedCount := 0
	clientIndex := 0
	trustedIndices := make([]int, 0, len(parts))

	hasCIDRs := len(e.config.trustedProxyCIDRs) > 0

	for i := len(parts) - 1; i >= 0; i-- {
		if !hasCIDRs && e.config.maxTrustedProxies > 0 && trustedCount >= e.config.maxTrustedProxies {
			clientIndex = i
			break
		}

		ip := parseIP(parts[i])

		if hasCIDRs && !e.isTrustedProxy(ip) {
			clientIndex = i
			break
		}

		trustedIndices = append(trustedIndices, i)
		trustedCount++
	}

	if err := e.validateProxyCount(trustedCount); err != nil {
		return chainAnalysis{
			clientIndex:    clientIndex,
			trustedCount:   trustedCount,
			trustedIndices: trustedIndices,
		}, err
	}

	return chainAnalysis{
		clientIndex:    clientIndex,
		trustedCount:   trustedCount,
		trustedIndices: trustedIndices,
	}, nil
}

func (e *Extractor) analyzeChainLeftmost(parts []string) (chainAnalysis, error) {
	if len(e.config.trustedProxyCIDRs) == 0 {
		return chainAnalysis{clientIndex: 0, trustedCount: 0}, nil
	}

	trustedCount := 0
	trustedIndices := make([]int, 0, len(parts))

	for i := len(parts) - 1; i >= 0; i-- {
		ip := parseIP(parts[i])
		if !e.isTrustedProxy(ip) {
			break
		}
		trustedIndices = append(trustedIndices, i)
		trustedCount++
	}

	if err := e.validateProxyCount(trustedCount); err != nil {
		return chainAnalysis{
			clientIndex:    0,
			trustedCount:   trustedCount,
			trustedIndices: trustedIndices,
		}, err
	}

	clientIndex := e.selectLeftmostUntrustedIP(parts, trustedCount)
	return chainAnalysis{
		clientIndex:    clientIndex,
		trustedCount:   trustedCount,
		trustedIndices: trustedIndices,
	}, nil
}

func (e *Extractor) selectLeftmostUntrustedIP(parts []string, trustedProxiesFromRight int) int {
	untrustedPortionEnd := max(len(parts)-trustedProxiesFromRight, 0)

	for i := range untrustedPortionEnd {
		if !e.isTrustedProxy(parseIP(parts[i])) {
			return i
		}
	}

	return max(untrustedPortionEnd-1, 0)
}

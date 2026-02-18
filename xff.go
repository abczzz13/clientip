package clientip

import (
	"net/netip"
	"strings"
)

// typicalChainCapacity is the default initial capacity used when parsing proxy
// chains.
const typicalChainCapacity = 8

func (e *Extractor) chainPartsCapacity(values []string) int {
	maxLength := e.config.maxChainLength
	if maxLength <= 0 {
		maxLength = 1
	}

	if len(values) == 1 {
		v := values[0]
		firstComma := strings.IndexByte(v, ',')
		if firstComma == -1 {
			return 1
		}

		secondComma := strings.IndexByte(v[firstComma+1:], ',')
		if secondComma == -1 {
			if maxLength < 2 {
				return maxLength
			}
			return 2
		}

		if strings.IndexByte(v[firstComma+secondComma+2:], ',') == -1 {
			if maxLength < 3 {
				return maxLength
			}
			return 3
		}
	} else if len(values) == 2 {
		if strings.IndexByte(values[0], ',') == -1 && strings.IndexByte(values[1], ',') == -1 {
			if maxLength < 2 {
				return maxLength
			}
			return 2
		}
	}

	if maxLength < typicalChainCapacity {
		return maxLength
	}

	return typicalChainCapacity
}

func trimHTTPWhitespace(value string) string {
	start := 0
	for start < len(value) {
		ch := value[start]
		if ch != ' ' && ch != '\t' {
			break
		}
		start++
	}

	end := len(value)
	for end > start {
		ch := value[end-1]
		if ch != ' ' && ch != '\t' {
			break
		}
		end--
	}

	return value[start:end]
}

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

	maxChainLength := e.config.maxChainLength
	parts := make([]string, 0, e.chainPartsCapacity(values))
	for _, v := range values {
		start := 0
		for i := 0; i <= len(v); i++ {
			if i != len(v) && v[i] != ',' {
				continue
			}

			part := trimHTTPWhitespace(v[start:i])
			if part != "" {
				if len(parts) >= maxChainLength {
					e.config.metrics.RecordSecurityEvent(securityEventChainTooLong)
					return nil, &ChainTooLongError{
						ExtractionError: ExtractionError{
							Err:    ErrChainTooLong,
							Source: SourceXForwardedFor,
						},
						ChainLength: len(parts) + 1,
						MaxLength:   maxChainLength,
					}
				}

				parts = append(parts, part)
			}

			start = i + 1
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
	leftmostUntrustedIndex := -1
	leftmostUntrustedIP := netip.Addr{}
	hasLeftmostUntrusted := false

	fallbackClientIndex := 0
	fallbackClientIP := netip.Addr{}
	hasFallbackClient := false

	var trustedIndices []int
	if collectTrustedIndices {
		trustedIndices = make([]int, 0, len(parts))
	}

	stillTrailingTrusted := true

	for i := len(parts) - 1; i >= 0; i-- {
		ip := parseIP(parts[i])
		isTrusted := e.isTrustedProxy(ip)

		if stillTrailingTrusted && isTrusted {
			if collectTrustedIndices {
				trustedIndices = append(trustedIndices, i)
			}
			trustedCount++
			continue
		}

		if stillTrailingTrusted {
			fallbackClientIndex = i
			fallbackClientIP = ip
			hasFallbackClient = true
		}

		stillTrailingTrusted = false
		if !isTrusted {
			leftmostUntrustedIndex = i
			leftmostUntrustedIP = ip
			hasLeftmostUntrusted = true
		}
	}

	analysis := chainAnalysis{
		trustedCount: trustedCount,
	}
	if collectTrustedIndices {
		analysis.trustedIndices = trustedIndices
	}

	if err := e.validateProxyCount(trustedCount); err != nil {
		return analysis, netip.Addr{}, err
	}

	if hasLeftmostUntrusted {
		analysis.clientIndex = leftmostUntrustedIndex
		return analysis, leftmostUntrustedIP, nil
	}

	if hasFallbackClient {
		analysis.clientIndex = fallbackClientIndex
		return analysis, fallbackClientIP, nil
	}

	analysis.clientIndex = 0
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
	untrustedPortionEnd := len(trustedFlags) - trustedProxiesFromRight
	if untrustedPortionEnd < 0 {
		untrustedPortionEnd = 0
	}

	for i := 0; i < untrustedPortionEnd; i++ {
		if !trustedFlags[i] {
			return i
		}
	}

	if untrustedPortionEnd <= 0 {
		return 0
	}

	return untrustedPortionEnd - 1
}

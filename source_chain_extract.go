package clientip

import (
	"net/netip"
	"strings"
)

type chainPolicy struct {
	headerName        string
	parseValues       func([]string) ([]string, error)
	clientIP          clientIPPolicy
	trustedProxy      proxyPolicy
	selection         ChainSelection
	collectDebugInfo  bool
	untrustedChainSep string
}

type chainExtractor struct {
	policy chainPolicy
}

func (e chainExtractor) extract(req requestView, source Source) (Extraction, *extractionFailure, error) {
	headerValues := req.valuesCanonical(e.policy.headerName)
	if len(headerValues) == 0 {
		return Extraction{}, errSourceUnavailable, nil
	}

	if len(e.policy.trustedProxy.TrustedProxyCIDRs) > 0 {
		remoteIP := parseRemoteAddr(req.remoteAddr())
		if !isTrustedProxy(remoteIP, e.policy.trustedProxy.TrustedProxyMatch, e.policy.trustedProxy.TrustedProxyCIDRs) {
			return Extraction{}, &extractionFailure{
				kind:              failureUntrustedProxy,
				source:            source,
				chain:             strings.Join(headerValues, e.chainSeparator()),
				trustedProxyCount: 0,
				minTrustedProxies: e.policy.trustedProxy.MinTrustedProxies,
				maxTrustedProxies: e.policy.trustedProxy.MaxTrustedProxies,
			}, nil
		}
	}

	parts, err := e.policy.parseValues(headerValues)
	if err != nil {
		return Extraction{}, nil, err
	}
	if len(parts) == 0 {
		return Extraction{}, &extractionFailure{kind: failureEmptyChain, source: source}, nil
	}

	analysis, clientIP, err := e.analyzeChain(parts)
	if err != nil {
		return Extraction{}, &extractionFailure{
			kind:              failureProxyValidation,
			source:            source,
			chain:             strings.Join(parts, ", "),
			trustedProxyCount: analysis.TrustedCount,
			minTrustedProxies: e.policy.trustedProxy.MinTrustedProxies,
			maxTrustedProxies: e.policy.trustedProxy.MaxTrustedProxies,
		}, nil
	}

	clientIPStr := parts[analysis.ClientIndex]
	disposition := evaluateClientIP(clientIP, e.policy.clientIP)
	if disposition != clientIPValid {
		return Extraction{}, &extractionFailure{
			kind:                failureInvalidClientIP,
			source:              source,
			chain:               strings.Join(parts, ", "),
			index:               analysis.ClientIndex,
			extractedIP:         clientIPStr,
			trustedProxyCount:   analysis.TrustedCount,
			clientIPDisposition: disposition,
		}, nil
	}

	result := Extraction{
		IP:                normalizeIP(clientIP),
		TrustedProxyCount: analysis.TrustedCount,
		Source:            source,
	}
	if e.policy.collectDebugInfo {
		result.DebugInfo = &ChainDebugInfo{
			FullChain:      parts,
			ClientIndex:    analysis.ClientIndex,
			TrustedIndices: analysis.TrustedIndices,
		}
	}

	return result, nil, nil
}

func (e chainExtractor) analyzeChain(parts []string) (chainAnalysis, netip.Addr, error) {
	if e.policy.selection == LeftmostUntrustedIP {
		return analyzeChainLeftmost(parts, e.policy.trustedProxy, e.policy.collectDebugInfo)
	}

	return analyzeChainRightmost(parts, e.policy.trustedProxy, e.policy.collectDebugInfo)
}

func (e chainExtractor) chainSeparator() string {
	if e.policy.untrustedChainSep != "" {
		return e.policy.untrustedChainSep
	}

	return ", "
}

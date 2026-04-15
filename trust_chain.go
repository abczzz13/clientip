package clientip

import (
	"net/netip"
)

type proxyPolicy struct {
	TrustedProxyCIDRs []netip.Prefix
	TrustedProxyMatch prefixMatcher
	MinTrustedProxies int
	MaxTrustedProxies int
}

type chainAnalysis struct {
	ClientIndex    int
	TrustedCount   int
	TrustedIndices []int
}

func isTrustedProxy(ip netip.Addr, matcher prefixMatcher, cidrs []netip.Prefix) bool {
	if !ip.IsValid() {
		return false
	}

	if matcher.initialized {
		return matcher.contains(ip)
	}

	for _, cidr := range cidrs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func validateProxyCountPolicy(trustedCount int, policy proxyPolicy) error {
	if len(policy.TrustedProxyCIDRs) > 0 && policy.MinTrustedProxies > 0 && trustedCount == 0 {
		return ErrNoTrustedProxies
	}

	if policy.MinTrustedProxies > 0 && trustedCount < policy.MinTrustedProxies {
		return ErrTooFewTrustedProxies
	}

	if policy.MaxTrustedProxies > 0 && trustedCount > policy.MaxTrustedProxies {
		return ErrTooManyTrustedProxies
	}

	return nil
}

func analyzeChainRightmost(parts []string, policy proxyPolicy, collectTrustedIndices bool) (chainAnalysis, netip.Addr, error) {
	trustedCount := 0
	clientIndex := 0
	clientIP := netip.Addr{}

	var trustedIndices []int
	if collectTrustedIndices {
		trustedIndices = make([]int, 0, len(parts))
	}

	hasCIDRs := len(policy.TrustedProxyCIDRs) > 0

	for i := len(parts) - 1; i >= 0; i-- {
		if !hasCIDRs && policy.MaxTrustedProxies > 0 && trustedCount >= policy.MaxTrustedProxies {
			clientIndex = i
			clientIP = parseChainIP(parts[i])
			break
		}

		ip := parseChainIP(parts[i])

		if hasCIDRs && !isTrustedProxy(ip, policy.TrustedProxyMatch, policy.TrustedProxyCIDRs) {
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
		ClientIndex:    clientIndex,
		TrustedCount:   trustedCount,
		TrustedIndices: trustedIndices,
	}

	if err := validateProxyCountPolicy(trustedCount, policy); err != nil {
		return analysis, netip.Addr{}, err
	}

	return analysis, clientIP, nil
}

func analyzeChainLeftmost(parts []string, policy proxyPolicy, collectTrustedIndices bool) (chainAnalysis, netip.Addr, error) {
	if len(policy.TrustedProxyCIDRs) == 0 {
		analysis := chainAnalysis{ClientIndex: 0, TrustedCount: 0}
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
		ip := parseChainIP(parts[i])
		trusted := isTrustedProxy(ip, policy.TrustedProxyMatch, policy.TrustedProxyCIDRs)

		if stillTrailingTrusted && trusted {
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
		if !trusted {
			leftmostUntrustedIndex = i
			leftmostUntrustedIP = ip
			hasLeftmostUntrusted = true
		}
	}

	analysis := chainAnalysis{TrustedCount: trustedCount}
	if collectTrustedIndices {
		analysis.TrustedIndices = trustedIndices
	}

	if err := validateProxyCountPolicy(trustedCount, policy); err != nil {
		return analysis, netip.Addr{}, err
	}

	if hasLeftmostUntrusted {
		analysis.ClientIndex = leftmostUntrustedIndex
		return analysis, leftmostUntrustedIP, nil
	}

	if hasFallbackClient {
		analysis.ClientIndex = fallbackClientIndex
		return analysis, fallbackClientIP, nil
	}

	analysis.ClientIndex = 0
	return analysis, parseChainIP(parts[analysis.ClientIndex]), nil
}

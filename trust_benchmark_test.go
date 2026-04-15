package clientip

import (
	"net/netip"
	"testing"
)

func BenchmarkIsTrustedProxy(b *testing.B) {
	cidrs := []netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("172.16.0.0/12"),
		netip.MustParsePrefix("192.168.0.0/16"),
	}
	matcher := newPrefixMatcher(cidrs)
	testIPs := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("172.16.0.1"),
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("1.1.1.1"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ip := range testIPs {
			isTrustedProxy(ip, matcher, cidrs)
		}
	}
}

func BenchmarkIsTrustedProxyLargeCIDRSetPrecomputed(b *testing.B) {
	const prefixCount = 4096
	prefixes := make([]netip.Prefix, 0, prefixCount)
	for i := 0; i < prefixCount; i++ {
		secondOctet := byte((i / 16) % 256)
		thirdOctet := byte(i % 256)
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, secondOctet, thirdOctet, 0}), 24))
	}

	matcher := newPrefixMatcher(prefixes)
	ip := netip.MustParseAddr("10.128.8.8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !isTrustedProxy(ip, matcher, prefixes) {
			b.Fatal("expected trusted proxy")
		}
	}
}

func BenchmarkIsTrustedProxyLargeCIDRSetLinearFallback(b *testing.B) {
	const prefixCount = 4096
	prefixes := make([]netip.Prefix, 0, prefixCount)
	for i := 0; i < prefixCount; i++ {
		secondOctet := byte((i / 16) % 256)
		thirdOctet := byte(i % 256)
		prefixes = append(prefixes, netip.PrefixFrom(netip.AddrFrom4([4]byte{10, secondOctet, thirdOctet, 0}), 24))
	}

	ip := netip.MustParseAddr("10.128.8.8")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if !isTrustedProxy(ip, prefixMatcher{}, prefixes) {
			b.Fatal("expected trusted proxy")
		}
	}
}

func BenchmarkChainAnalysisRightmost(b *testing.B) {
	policy := proxyPolicy{
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		MinTrustedProxies: 1,
		MaxTrustedProxies: 3,
	}
	policy.TrustedProxyMatch = newPrefixMatcher(policy.TrustedProxyCIDRs)
	parts := []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "10.0.0.2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := analyzeChainRightmost(parts, policy, true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChainAnalysisLeftmost(b *testing.B) {
	policy := proxyPolicy{
		TrustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		MinTrustedProxies: 1,
		MaxTrustedProxies: 3,
	}
	policy.TrustedProxyMatch = newPrefixMatcher(policy.TrustedProxyCIDRs)
	parts := []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "10.0.0.2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := analyzeChainLeftmost(parts, policy, true)
		if err != nil {
			b.Fatal(err)
		}
	}
}

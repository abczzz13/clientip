package clientip

import (
	"net/netip"
	"testing"
)

func TestTrustedProxyMatcher_Contains(t *testing.T) {
	matcher := buildTrustedProxyMatcher([]netip.Prefix{
		netip.MustParsePrefix("10.0.0.0/8"),
		netip.MustParsePrefix("2001:db8::/32"),
	})

	tests := []struct {
		name string
		ip   netip.Addr
		want bool
	}{
		{name: "IPv4 in range", ip: netip.MustParseAddr("10.42.1.2"), want: true},
		{name: "IPv4 out of range", ip: netip.MustParseAddr("11.0.0.1"), want: false},
		{name: "IPv6 in range", ip: netip.MustParseAddr("2001:db8::1"), want: true},
		{name: "IPv6 out of range", ip: netip.MustParseAddr("2606:4700::1"), want: false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matcher.contains(tt.ip); got != tt.want {
				t.Fatalf("matcher.contains(%v) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestTrustedProxyMatcher_ZeroPrefix(t *testing.T) {
	v4Matcher := buildTrustedProxyMatcher([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if !v4Matcher.contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected IPv4 matcher to trust all IPv4 addresses")
	}
	if v4Matcher.contains(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatal("expected IPv4 matcher to reject IPv6 addresses")
	}

	v6Matcher := buildTrustedProxyMatcher([]netip.Prefix{netip.MustParsePrefix("::/0")})
	if !v6Matcher.contains(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatal("expected IPv6 matcher to trust all IPv6 addresses")
	}
	if v6Matcher.contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected IPv6 matcher to reject IPv4 addresses")
	}
}

func TestIsTrustedProxy_UsesPrecomputedMatcher(t *testing.T) {
	extractor, err := New(TrustedCIDRs("10.0.0.0/8"))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if !extractor.config.trustedProxyMatch.initialized {
		t.Fatal("expected precomputed trusted proxy matcher to be initialized")
	}

	if !extractor.isTrustedProxy(netip.MustParseAddr("10.12.1.3")) {
		t.Fatal("expected address to be trusted")
	}
	if extractor.isTrustedProxy(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected address to be untrusted")
	}
}

func TestIsTrustedProxy_LinearFallbackWhenMatcherMissing(t *testing.T) {
	extractor := &Extractor{
		config: &config{
			trustedProxyCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
		},
	}

	if extractor.config.trustedProxyMatch.initialized {
		t.Fatal("expected matcher to be uninitialized for manual config")
	}

	if !extractor.isTrustedProxy(netip.MustParseAddr("10.12.1.3")) {
		t.Fatal("expected address to be trusted via linear fallback")
	}
	if extractor.isTrustedProxy(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected address to be untrusted via linear fallback")
	}
}

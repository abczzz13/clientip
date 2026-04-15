package clientip

import (
	"net/netip"
	"testing"
)

func TestMatcherContains(t *testing.T) {
	matcher := newPrefixMatcher([]netip.Prefix{
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

func TestMatcherZeroPrefix(t *testing.T) {
	v4Matcher := newPrefixMatcher([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if !v4Matcher.contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected IPv4 matcher to trust all IPv4 addresses")
	}
	if v4Matcher.contains(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatal("expected IPv4 matcher to reject IPv6 addresses")
	}

	v6Matcher := newPrefixMatcher([]netip.Prefix{netip.MustParsePrefix("::/0")})
	if !v6Matcher.contains(netip.MustParseAddr("2001:4860:4860::8888")) {
		t.Fatal("expected IPv6 matcher to trust all IPv6 addresses")
	}
	if v6Matcher.contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("expected IPv6 matcher to reject IPv4 addresses")
	}
}

func TestIsTrustedProxyUsesMatcher(t *testing.T) {
	matcher := newPrefixMatcher([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")})
	if !matcher.initialized {
		t.Fatal("expected matcher to be initialized")
	}

	if !isTrustedProxy(netip.MustParseAddr("10.12.1.3"), matcher, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Fatal("expected address to be trusted")
	}
	if isTrustedProxy(netip.MustParseAddr("8.8.8.8"), matcher, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Fatal("expected address to be untrusted")
	}
}

func TestIsTrustedProxyLinearFallbackWhenMatcherMissing(t *testing.T) {
	if !isTrustedProxy(netip.MustParseAddr("10.12.1.3"), prefixMatcher{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Fatal("expected address to be trusted via linear fallback")
	}
	if isTrustedProxy(netip.MustParseAddr("8.8.8.8"), prefixMatcher{}, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}) {
		t.Fatal("expected address to be untrusted via linear fallback")
	}
}

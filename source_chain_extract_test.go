package clientip

import (
	"errors"
	"net/netip"
	"strings"
	"testing"
)

// simpleXFFParse is a minimal comma-split parser for tests.
func simpleXFFParse(values []string) ([]string, error) {
	var parts []string
	for _, v := range values {
		for _, seg := range strings.Split(v, ",") {
			seg = strings.TrimSpace(seg)
			if seg != "" {
				parts = append(parts, seg)
			}
		}
	}
	return parts, nil
}

func TestChainExtractor_HeaderMissing(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		selection:   RightmostUntrustedIP,
	}}

	req := requestView{
		headerMap: map[string][]string{},
	}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure != errSourceUnavailable {
		t.Errorf("failure = %+v, want errSourceUnavailable", failure)
	}
}

func TestChainExtractor_SingleValidValue(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		selection:   RightmostUntrustedIP,
	}}

	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"8.8.8.8"},
		},
	}

	result, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("8.8.8.8")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Source != SourceXForwardedFor {
		t.Errorf("Source = %v, want %v", result.Source, SourceXForwardedFor)
	}
}

func TestChainExtractor_ChainWithTrustedProxies(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("10.0.0.0/8")
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		trustedProxy: proxyPolicy{
			TrustedProxyCIDRs: []netip.Prefix{trustedCIDR},
			TrustedProxyMatch: newPrefixMatcher([]netip.Prefix{trustedCIDR}),
		},
		selection: RightmostUntrustedIP,
	}}

	// Chain: client, proxy1, proxy2
	// 10.0.0.x are trusted, so client IP should be 8.8.8.8
	req := requestView{
		remoteAddrValue: "10.0.0.3:8080",
		headerMap: map[string][]string{
			"X-Forwarded-For": {"8.8.8.8, 10.0.0.1, 10.0.0.2"},
		},
	}

	result, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("8.8.8.8")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.TrustedProxyCount != 2 {
		t.Errorf("TrustedProxyCount = %d, want 2", result.TrustedProxyCount)
	}
}

func TestChainExtractor_EmptyChainAfterParse(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName: "X-Forwarded-For",
		parseValues: func(values []string) ([]string, error) {
			return nil, nil // empty result
		},
		selection: RightmostUntrustedIP,
	}}

	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"  "},
		},
	}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureEmptyChain {
		t.Errorf("failure.kind = %v, want failureEmptyChain", failure.kind)
	}
}

func TestChainExtractor_UntrustedProxy(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("10.0.0.0/8")
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		trustedProxy: proxyPolicy{
			TrustedProxyCIDRs: []netip.Prefix{trustedCIDR},
			TrustedProxyMatch: newPrefixMatcher([]netip.Prefix{trustedCIDR}),
		},
		selection: RightmostUntrustedIP,
	}}

	// Remote addr is NOT trusted.
	req := requestView{
		remoteAddrValue: "5.5.5.5:4567",
		headerMap: map[string][]string{
			"X-Forwarded-For": {"9.9.9.9"},
		},
	}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureUntrustedProxy {
		t.Errorf("failure.kind = %v, want failureUntrustedProxy", failure.kind)
	}
}

func TestChainExtractor_DebugInfoCollected(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("10.0.0.0/8")
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		trustedProxy: proxyPolicy{
			TrustedProxyCIDRs: []netip.Prefix{trustedCIDR},
			TrustedProxyMatch: newPrefixMatcher([]netip.Prefix{trustedCIDR}),
		},
		selection:        RightmostUntrustedIP,
		collectDebugInfo: true,
	}}

	req := requestView{
		remoteAddrValue: "10.0.0.3:8080",
		headerMap: map[string][]string{
			"X-Forwarded-For": {"8.8.8.8, 10.0.0.1, 10.0.0.2"},
		},
	}

	result, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	if result.DebugInfo == nil {
		t.Fatal("expected DebugInfo to be set")
	}
	if len(result.DebugInfo.FullChain) != 3 {
		t.Errorf("FullChain length = %d, want 3", len(result.DebugInfo.FullChain))
	}
	if result.DebugInfo.ClientIndex != 0 {
		t.Errorf("ClientIndex = %d, want 0", result.DebugInfo.ClientIndex)
	}
	if len(result.DebugInfo.TrustedIndices) != 2 {
		t.Errorf("TrustedIndices length = %d, want 2", len(result.DebugInfo.TrustedIndices))
	}
}

func TestChainExtractor_DebugInfoNotCollectedByDefault(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:       "X-Forwarded-For",
		parseValues:      simpleXFFParse,
		selection:        RightmostUntrustedIP,
		collectDebugInfo: false,
	}}

	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"8.8.8.8"},
		},
	}

	result, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	if result.DebugInfo != nil {
		t.Error("expected DebugInfo to be nil when collectDebugInfo is false")
	}
}

func TestChainExtractor_InvalidClientIP(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		selection:   RightmostUntrustedIP,
	}}

	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"not-valid-ip"},
		},
	}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
	if failure.extractedIP != "not-valid-ip" {
		t.Errorf("failure.extractedIP = %q, want %q", failure.extractedIP, "not-valid-ip")
	}
}

func TestChainExtractor_ParseValuesError(t *testing.T) {
	parseErr := &chainTooLongParseError{ChainLength: 100, MaxLength: 50}
	ext := chainExtractor{policy: chainPolicy{
		headerName: "X-Forwarded-For",
		parseValues: func(values []string) ([]string, error) {
			return nil, parseErr
		},
		selection: RightmostUntrustedIP,
	}}

	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"a, b, c"},
		},
	}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err == nil {
		t.Fatal("expected error from parseValues, got nil")
	}
	if failure != nil {
		t.Errorf("failure should be nil when parseValues returns error, got %+v", failure)
	}
	if !errors.Is(err, parseErr) {
		t.Errorf("error = %v, want %v", err, parseErr)
	}
}

func TestChainExtractor_MultipleHeaderValues(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		selection:   RightmostUntrustedIP,
	}}

	// Multiple X-Forwarded-For header values (as separate entries).
	// simpleXFFParse treats them as two separate chain parts.
	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
		},
	}

	result, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	// With no trusted CIDRs and no MaxTrustedProxies, every entry is walked
	// as trusted. The leftmost entry (index 0) becomes the client IP.
	wantIP := netip.MustParseAddr("8.8.8.8")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestChainExtractor_LoopbackClientIPRejected(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		selection:   RightmostUntrustedIP,
	}}

	req := requestView{
		headerMap: map[string][]string{
			"X-Forwarded-For": {"127.0.0.1"},
		},
	}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure == nil {
		t.Fatal("expected failure for loopback client IP")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
}

func TestChainExtractor_NoHeadersAtAll(t *testing.T) {
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		selection:   RightmostUntrustedIP,
	}}

	req := requestView{}

	_, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure != errSourceUnavailable {
		t.Errorf("failure = %+v, want errSourceUnavailable", failure)
	}
}

func TestChainExtractor_IPv6InChain(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("fd00::/8")
	ext := chainExtractor{policy: chainPolicy{
		headerName:  "X-Forwarded-For",
		parseValues: simpleXFFParse,
		trustedProxy: proxyPolicy{
			TrustedProxyCIDRs: []netip.Prefix{trustedCIDR},
			TrustedProxyMatch: newPrefixMatcher([]netip.Prefix{trustedCIDR}),
		},
		selection: RightmostUntrustedIP,
	}}

	req := requestView{
		remoteAddrValue: "[fd00::3]:8080",
		headerMap: map[string][]string{
			"X-Forwarded-For": {"2606:4700::1, fd00::1, fd00::2"},
		},
	}

	result, failure, err := ext.extract(req, SourceXForwardedFor)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("2606:4700::1")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

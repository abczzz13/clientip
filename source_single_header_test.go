package clientip

import (
	"net/netip"
	"testing"
)

func TestSingleHeaderExtractor_ValidIP(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	source := SourceXRealIP
	req := requestView{
		remoteAddrValue: "10.0.0.1:1234",
		headerMap: map[string][]string{
			"X-Real-Ip": {"8.8.8.8"},
		},
	}

	result, failure := ext.extract(req, source)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("8.8.8.8")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Source != source {
		t.Errorf("Source = %v, want %v", result.Source, source)
	}
}

func TestSingleHeaderExtractor_HeaderMissing(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	req := requestView{
		headerMap: map[string][]string{},
	}

	_, failure := ext.extract(req, SourceXRealIP)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure != errSourceUnavailable {
		t.Errorf("failure = %+v, want errSourceUnavailable", failure)
	}
}

func TestSingleHeaderExtractor_EmptyHeaderValue(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	req := requestView{
		headerMap: map[string][]string{
			"X-Real-Ip": {""},
		},
	}

	_, failure := ext.extract(req, SourceXRealIP)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure != errSourceUnavailable {
		t.Errorf("failure = %+v, want errSourceUnavailable", failure)
	}
}

func TestSingleHeaderExtractor_MultipleHeaderValues(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	req := requestView{
		remoteAddrValue: "10.0.0.1:1234",
		headerMap: map[string][]string{
			"X-Real-Ip": {"8.8.4.4", "1.1.1.1"},
		},
	}

	_, failure := ext.extract(req, SourceXRealIP)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureMultipleHeaders {
		t.Errorf("failure.kind = %v, want failureMultipleHeaders", failure.kind)
	}
	if failure.headerCount != 2 {
		t.Errorf("failure.headerCount = %d, want 2", failure.headerCount)
	}
	if failure.headerName != "X-Real-Ip" {
		t.Errorf("failure.headerName = %q, want %q", failure.headerName, "X-Real-Ip")
	}
}

func TestSingleHeaderExtractor_UntrustedProxy(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("10.0.0.0/8")
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
		trustedProxy: proxyPolicy{
			TrustedProxyCIDRs: []netip.Prefix{trustedCIDR},
			TrustedProxyMatch: newPrefixMatcher([]netip.Prefix{trustedCIDR}),
		},
	}}
	// Remote addr is not in trusted CIDR.
	req := requestView{
		remoteAddrValue: "5.5.5.5:4567",
		headerMap: map[string][]string{
			"X-Real-Ip": {"9.9.9.9"},
		},
	}

	_, failure := ext.extract(req, SourceXRealIP)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureUntrustedProxy {
		t.Errorf("failure.kind = %v, want failureUntrustedProxy", failure.kind)
	}
}

func TestSingleHeaderExtractor_TrustedProxy(t *testing.T) {
	trustedCIDR := netip.MustParsePrefix("10.0.0.0/8")
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
		trustedProxy: proxyPolicy{
			TrustedProxyCIDRs: []netip.Prefix{trustedCIDR},
			TrustedProxyMatch: newPrefixMatcher([]netip.Prefix{trustedCIDR}),
		},
	}}
	// Remote addr IS in trusted CIDR.
	req := requestView{
		remoteAddrValue: "10.0.0.1:4567",
		headerMap: map[string][]string{
			"X-Real-Ip": {"9.9.9.9"},
		},
	}

	result, failure := ext.extract(req, SourceXRealIP)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("9.9.9.9")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestSingleHeaderExtractor_InvalidClientIP(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	req := requestView{
		headerMap: map[string][]string{
			"X-Real-Ip": {"not-an-ip"},
		},
	}

	_, failure := ext.extract(req, SourceXRealIP)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
	if failure.extractedIP != "not-an-ip" {
		t.Errorf("failure.extractedIP = %q, want %q", failure.extractedIP, "not-an-ip")
	}
}

func TestSingleHeaderExtractor_LoopbackIsInvalidClient(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	req := requestView{
		headerMap: map[string][]string{
			"X-Real-Ip": {"127.0.0.1"},
		},
	}

	_, failure := ext.extract(req, SourceXRealIP)
	if failure == nil {
		t.Fatal("expected failure for loopback IP, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
}

func TestSingleHeaderExtractor_IPv6(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Real-Ip",
	}}
	req := requestView{
		headerMap: map[string][]string{
			"X-Real-Ip": {"2606:4700::1"},
		},
	}

	result, failure := ext.extract(req, SourceXRealIP)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("2606:4700::1")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestSingleHeaderExtractor_NoHeadersAtAll(t *testing.T) {
	ext := singleHeaderExtractor{policy: singleHeaderPolicy{
		headerName: "X-Custom",
	}}
	req := requestView{}

	_, failure := ext.extract(req, HeaderSource("X-Custom"))
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure != errSourceUnavailable {
		t.Errorf("failure = %+v, want errSourceUnavailable", failure)
	}
}

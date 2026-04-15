package clientip

import (
	"net/netip"
	"testing"
)

func TestRemoteAddrExtractor_ValidAddr(t *testing.T) {
	ext := remoteAddrExtractor{}
	source := SourceRemoteAddr

	result, failure := ext.extract("8.8.8.8:8080", source)
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

func TestRemoteAddrExtractor_ValidAddrWithoutPort(t *testing.T) {
	ext := remoteAddrExtractor{}
	source := SourceRemoteAddr

	result, failure := ext.extract("8.8.8.8", source)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("8.8.8.8")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestRemoteAddrExtractor_IPv6(t *testing.T) {
	ext := remoteAddrExtractor{}
	source := SourceRemoteAddr

	result, failure := ext.extract("[2606:4700::1]:443", source)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("2606:4700::1")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestRemoteAddrExtractor_EmptyAddr(t *testing.T) {
	ext := remoteAddrExtractor{}

	_, failure := ext.extract("", SourceRemoteAddr)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure != errSourceUnavailable {
		t.Errorf("failure = %+v, want errSourceUnavailable", failure)
	}
}

func TestRemoteAddrExtractor_InvalidIP(t *testing.T) {
	ext := remoteAddrExtractor{}

	_, failure := ext.extract("not-an-ip", SourceRemoteAddr)
	if failure == nil {
		t.Fatal("expected failure, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
}

func TestRemoteAddrExtractor_LoopbackIP(t *testing.T) {
	ext := remoteAddrExtractor{}

	_, failure := ext.extract("127.0.0.1:8080", SourceRemoteAddr)
	if failure == nil {
		t.Fatal("expected failure for loopback, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
}

func TestRemoteAddrExtractor_UnspecifiedIP(t *testing.T) {
	ext := remoteAddrExtractor{}

	_, failure := ext.extract("0.0.0.0:80", SourceRemoteAddr)
	if failure == nil {
		t.Fatal("expected failure for unspecified IP, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
}

func TestRemoteAddrExtractor_PrivateIPRejectedByDefault(t *testing.T) {
	ext := remoteAddrExtractor{}

	_, failure := ext.extract("192.168.1.1:80", SourceRemoteAddr)
	if failure == nil {
		t.Fatal("expected failure for private IP with default policy, got nil")
	}
	if failure.kind != failureInvalidClientIP {
		t.Errorf("failure.kind = %v, want failureInvalidClientIP", failure.kind)
	}
}

func TestRemoteAddrExtractor_PrivateIPAllowed(t *testing.T) {
	ext := remoteAddrExtractor{
		clientIPPolicy: clientIPPolicy{AllowPrivateIPs: true},
	}

	result, failure := ext.extract("192.168.1.1:80", SourceRemoteAddr)
	if failure != nil {
		t.Fatalf("unexpected failure: %+v", failure)
	}
	wantIP := netip.MustParseAddr("192.168.1.1")
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestRemoteAddrExtractor_SourcePreserved(t *testing.T) {
	ext := remoteAddrExtractor{}
	source := SourceRemoteAddr

	_, failure := ext.extract("not-valid", source)
	if failure == nil {
		t.Fatal("expected failure")
	}
	if failure.source != source {
		t.Errorf("failure.source = %v, want %v", failure.source, source)
	}
}

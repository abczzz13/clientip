package clientip

import (
	"net/http"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPresetDirectConnection(t *testing.T) {
	cfg := defaultConfig()
	if err := PresetDirectConnection()(cfg); err != nil {
		t.Fatalf("PresetDirectConnection() error = %v", err)
	}

	want := []string{SourceRemoteAddr}
	if diff := cmp.Diff(want, cfg.sourcePriority); diff != "" {
		t.Fatalf("sourcePriority mismatch (-want +got):\n%s", diff)
	}
}

func TestPresetLoopbackReverseProxy(t *testing.T) {
	cfg := defaultConfig()
	if err := PresetLoopbackReverseProxy()(cfg); err != nil {
		t.Fatalf("PresetLoopbackReverseProxy() error = %v", err)
	}

	wantSources := []string{SourceXForwardedFor, SourceRemoteAddr}
	if diff := cmp.Diff(wantSources, cfg.sourcePriority); diff != "" {
		t.Fatalf("sourcePriority mismatch (-want +got):\n%s", diff)
	}

	for _, cidr := range []string{"127.0.0.0/8", "::1/128"} {
		wantPrefix := netip.MustParsePrefix(cidr)
		if !containsPrefix(cfg.trustedProxyCIDRs, wantPrefix) {
			t.Fatalf("trustedProxyCIDRs missing %s", wantPrefix)
		}
	}
}

func TestPresetVMReverseProxy(t *testing.T) {
	cfg := defaultConfig()
	if err := PresetVMReverseProxy()(cfg); err != nil {
		t.Fatalf("PresetVMReverseProxy() error = %v", err)
	}

	wantSources := []string{SourceXForwardedFor, SourceRemoteAddr}
	if diff := cmp.Diff(wantSources, cfg.sourcePriority); diff != "" {
		t.Fatalf("sourcePriority mismatch (-want +got):\n%s", diff)
	}

	for _, cidr := range []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"} {
		wantPrefix := netip.MustParsePrefix(cidr)
		if !containsPrefix(cfg.trustedProxyCIDRs, wantPrefix) {
			t.Fatalf("trustedProxyCIDRs missing %s", wantPrefix)
		}
	}
}

func TestPresetPreferredHeaderThenXFFLax(t *testing.T) {
	cfg := defaultConfig()
	if err := PresetPreferredHeaderThenXFFLax("X-Frontend-IP")(cfg); err != nil {
		t.Fatalf("PresetPreferredHeaderThenXFFLax() error = %v", err)
	}

	wantSources := []string{"X-Frontend-IP", SourceXForwardedFor, SourceRemoteAddr}
	if diff := cmp.Diff(wantSources, cfg.sourcePriority); diff != "" {
		t.Fatalf("sourcePriority mismatch (-want +got):\n%s", diff)
	}

	if cfg.securityMode != SecurityModeLax {
		t.Fatalf("securityMode = %v, want %v", cfg.securityMode, SecurityModeLax)
	}
}

func TestPresetPreferredHeaderThenXFFLax_InvalidHeader(t *testing.T) {
	cfg := defaultConfig()
	if err := PresetPreferredHeaderThenXFFLax("  ")(cfg); err == nil {
		t.Fatal("PresetPreferredHeaderThenXFFLax() error = nil, want non-nil")
	}
}

func TestPresetVMReverseProxy_EndToEnd(t *testing.T) {
	extractor, err := New(PresetVMReverseProxy())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result := extractor.ExtractIP(req)
	if !result.Valid() {
		t.Fatalf("ExtractIP() error = %v", result.Err)
	}
	if got, want := result.Source, SourceXForwardedFor; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
}

func TestPresetPreferredHeaderThenXFFLax_EndToEnd(t *testing.T) {
	extractor, err := New(
		TrustLoopbackProxy(),
		PresetPreferredHeaderThenXFFLax("X-Frontend-IP"),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Frontend-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	result := extractor.ExtractIP(req)
	if !result.Valid() {
		t.Fatalf("ExtractIP() error = %v", result.Err)
	}
	if got, want := result.Source, SourceXForwardedFor; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
	if got, want := result.IP, netip.MustParseAddr("8.8.8.8"); got != want {
		t.Fatalf("ip = %v, want %v", got, want)
	}
}

func containsPrefix(prefixes []netip.Prefix, want netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == want {
			return true
		}
	}

	return false
}

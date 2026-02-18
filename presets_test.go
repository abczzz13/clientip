package clientip

import (
	"net/http"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPresets_Config(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		want        configSnapshot
		wantErrText string
	}{
		{
			name: "direct connection",
			opts: []Option{PresetDirectConnection()},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				SecurityMode:          SecurityModeStrict,
				DebugMode:             false,
				SourcePriority:        []string{SourceRemoteAddr},
			},
		},
		{
			name: "loopback reverse proxy",
			opts: []Option{PresetLoopbackReverseProxy()},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"127.0.0.0/8", "::1/128"},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				SecurityMode:          SecurityModeStrict,
				DebugMode:             false,
				SourcePriority:        []string{SourceXForwardedFor, SourceRemoteAddr},
			},
		},
		{
			name: "vm reverse proxy",
			opts: []Option{PresetVMReverseProxy()},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				SecurityMode:          SecurityModeStrict,
				DebugMode:             false,
				SourcePriority:        []string{SourceXForwardedFor, SourceRemoteAddr},
			},
		},
		{
			name: "preferred header then xff lax invalid header",
			opts: []Option{
				TrustLoopbackProxy(),
				PresetPreferredHeaderThenXFFLax("  "),
			},
			wantErrText: "source names cannot be empty",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := New(tt.opts...)
			if tt.wantErrText != "" {
				if err == nil {
					t.Fatalf("New() error = nil, want containing %q", tt.wantErrText)
				}
				if !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("New() error = %q, want containing %q", err.Error(), tt.wantErrText)
				}
				return
			}

			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, snapshotConfig(extractor.config)); diff != "" {
				t.Fatalf("preset config mismatch (-want +got):\n%s", diff)
			}
		})
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

	extraction, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	want := struct {
		IP                string
		Source            string
		TrustedProxyCount int
		HasDebugInfo      bool
	}{
		IP:                "8.8.8.8",
		Source:            SourceXForwardedFor,
		TrustedProxyCount: 0,
		HasDebugInfo:      false,
	}
	got := struct {
		IP                string
		Source            string
		TrustedProxyCount int
		HasDebugInfo      bool
	}{
		IP:                extraction.IP.String(),
		Source:            extraction.Source,
		TrustedProxyCount: extraction.TrustedProxyCount,
		HasDebugInfo:      extraction.DebugInfo != nil,
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("extraction mismatch (-want +got):\n%s", diff)
	}
}

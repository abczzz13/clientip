package clientip

import (
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestPresets_Config(t *testing.T) {
	tests := []struct {
		name        string
		opt         Option
		want        configSnapshot
		wantErrText string
	}{
		{
			name: "direct connection",
			opt:  PresetDirectConnection(),
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				DebugMode:             false,
				SourcePriority:        []string{SourceRemoteAddr.String()},
			},
		},
		{
			name: "loopback reverse proxy",
			opt:  PresetLoopbackReverseProxy(),
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"127.0.0.0/8", "::1/128"},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				DebugMode:             false,
				SourcePriority:        []string{SourceXForwardedFor.String(), SourceRemoteAddr.String()},
			},
		},
		{
			name: "vm reverse proxy",
			opt:  PresetVMReverseProxy(),
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"127.0.0.0/8", "::1/128", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				DebugMode:             false,
				SourcePriority:        []string{SourceXForwardedFor.String(), SourceRemoteAddr.String()},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resolver, err := New(tt.opt)
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

			if diff := cmp.Diff(tt.want, snapshotConfig(resolver.extractor.config)); diff != "" {
				t.Fatalf("preset config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

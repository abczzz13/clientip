package clientip

import (
	"io"
	"log/slog"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type testTypedNilMetrics struct{}

func (*testTypedNilMetrics) RecordExtractionSuccess(string) {}

func (*testTypedNilMetrics) RecordExtractionFailure(string) {}

func (*testTypedNilMetrics) RecordSecurityEvent(string) {}

type configSnapshot struct {
	TrustedProxyCIDRs     []string
	MinTrustedProxies     int
	MaxTrustedProxies     int
	AllowPrivateIPs       bool
	AllowReservedPrefixes []string
	MaxChainLength        int
	ChainSelection        ChainSelection
	DebugMode             bool
	SourcePriority        []string
}

func snapshotConfig(cfg *config) configSnapshot {
	trusted := make([]string, len(cfg.trustedProxyCIDRs))
	for i, prefix := range cfg.trustedProxyCIDRs {
		trusted[i] = prefix.String()
	}

	return configSnapshot{
		TrustedProxyCIDRs:     trusted,
		MinTrustedProxies:     cfg.minTrustedProxies,
		MaxTrustedProxies:     cfg.maxTrustedProxies,
		AllowPrivateIPs:       cfg.allowPrivateIPs,
		AllowReservedPrefixes: cidrStrings(cfg.allowReservedClientPrefixes),
		MaxChainLength:        cfg.maxChainLength,
		ChainSelection:        cfg.chainSelection,
		DebugMode:             cfg.debugMode,
		SourcePriority:        sourceNames(cfg.sourcePriority),
	}
}

func cidrStrings(prefixes []netip.Prefix) []string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	return values
}

func sourceNames(sources []Source) []string {
	values := make([]string, len(sources))
	for i, source := range sources {
		values[i] = source.name()
	}
	return values
}

func TestNew_ConfigScenarios(t *testing.T) {
	tests := []struct {
		name        string
		buildConfig func() Config
		want        configSnapshot
		wantErrText string
	}{
		{
			name: "default",
			buildConfig: func() Config {
				return DefaultConfig()
			},
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
			name: "configured config",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("172.16.0.0/12"),
				}
				cfg.MinTrustedProxies = 1
				cfg.MaxTrustedProxies = 3
				cfg.AllowPrivateIPs = true
				cfg.AllowedReservedClientPrefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
				cfg.MaxChainLength = 42
				cfg.ChainSelection = LeftmostUntrustedIP
				cfg.DebugInfo = true
				cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
				return cfg
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12"},
				MinTrustedProxies:     1,
				MaxTrustedProxies:     3,
				AllowPrivateIPs:       true,
				AllowReservedPrefixes: []string{"198.51.100.0/24"},
				MaxChainLength:        42,
				ChainSelection:        LeftmostUntrustedIP,
				DebugMode:             true,
				SourcePriority:        []string{SourceXForwardedFor.String(), SourceRemoteAddr.String()},
			},
		},
		{
			name: "merge option fragments",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
				cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
				return cfg
			},
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
			name: "merge trusted proxy prefixes",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("172.16.0.0/12"),
				}
				return cfg
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12"},
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
			name: "merge reserved client prefixes",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.AllowedReservedClientPrefixes = []netip.Prefix{
					netip.MustParsePrefix("198.51.100.0/24"),
					netip.MustParsePrefix("198.51.100.0/24"),
					netip.MustParsePrefix("203.0.113.0/24"),
				}
				return cfg
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{"198.51.100.0/24", "203.0.113.0/24"},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				DebugMode:             false,
				SourcePriority:        []string{SourceRemoteAddr.String()},
			},
		},
		{
			name: "invalid trusted prefix helper",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = []netip.Prefix{{}}
				return cfg
			},
			wantErrText: "invalid trusted proxy prefix",
		},
		{
			name: "invalid allow reserved prefix helper",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.AllowedReservedClientPrefixes = []netip.Prefix{{}}
				return cfg
			},
			wantErrText: "invalid reserved client prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := New(tt.buildConfig())
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
				t.Fatalf("config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNew_InvalidConfig(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		buildConfig func() Config
		wantErrText string
	}{
		{
			name: "min exceeds max",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
				cfg.MinTrustedProxies = 5
				cfg.MaxTrustedProxies = 2
				return cfg
			},
			wantErrText: "minTrustedProxies",
		},
		{
			name: "header source without trusted proxies",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Sources = []Source{SourceXForwardedFor}
				return cfg
			},
			wantErrText: "header-based sources require trusted proxy prefixes",
		},
		{
			name: "invalid chain selection",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.ChainSelection = ChainSelection(999)
				return cfg
			},
			wantErrText: "invalid chain selection",
		},
		{
			name: "empty explicit source priority",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Sources = []Source{}
				return cfg
			},
			wantErrText: "at least one source required",
		},
		{
			name: "typed nil logger",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Logger = (*slog.Logger)(nil)
				return cfg
			},
			wantErrText: "logger cannot be nil",
		},
		{
			name: "typed nil metrics",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Metrics = (*testTypedNilMetrics)(nil)
				return cfg
			},
			wantErrText: "metrics cannot be nil",
		},
		{
			name: "leftmost without trusted proxies",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Sources = []Source{SourceXForwardedFor}
				cfg.ChainSelection = LeftmostUntrustedIP
				return cfg
			},
			wantErrText: "LeftmostUntrustedIP selection requires trusted proxy prefixes",
		},
		{
			name: "multiple chain sources",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}
				cfg.Sources = []Source{SourceForwarded, SourceXForwardedFor}
				cfg.Logger = logger
				return cfg
			},
			wantErrText: "priority cannot include both",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.buildConfig())
			if err == nil {
				t.Fatalf("New() error = nil, want containing %q", tt.wantErrText)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("New() error = %q, want containing %q", err.Error(), tt.wantErrText)
			}
		})
	}
}

func TestNew_InvalidBoundsAndDuplicatePriority(t *testing.T) {
	tests := []struct {
		name        string
		buildConfig func() Config
		wantSources []Source
		wantErrText string
	}{
		{
			name: "negative min trusted proxies",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.MinTrustedProxies = -1
				return cfg
			},
			wantErrText: "minTrustedProxies must be >= 0",
		},
		{
			name: "negative max trusted proxies",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.MaxTrustedProxies = -1
				return cfg
			},
			wantErrText: "maxTrustedProxies must be >= 0",
		},
		{
			name: "negative max chain length",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.MaxChainLength = -1
				return cfg
			},
			wantErrText: "maxChainLength must be > 0",
		},
		{
			name: "duplicate source in priority",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Sources = []Source{SourceRemoteAddr, SourceRemoteAddr}
				return cfg
			},
			wantErrText: "duplicate source",
		},
		{
			name: "duplicate source after canonicalization",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
				cfg.Sources = []Source{SourceXForwardedFor, HeaderSource("X-Forwarded-For")}
				return cfg
			},
			wantErrText: "duplicate source",
		},
		{
			name: "resolver-only static fallback source",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.Sources = []Source{SourceStaticFallback}
				return cfg
			},
			wantErrText: "resolver-only and cannot be used in Config.Sources",
		},
		{
			name: "distinct custom headers with different runtime keys",
			buildConfig: func() Config {
				cfg := DefaultConfig()
				cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
				cfg.Sources = []Source{HeaderSource("Foo-Bar"), HeaderSource("Foo_Bar")}
				return cfg
			},
			wantSources: []Source{HeaderSource("Foo-Bar"), HeaderSource("Foo_Bar")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := New(tt.buildConfig())
			if tt.wantErrText == "" && tt.wantSources != nil {
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}

				if diff := cmp.Diff(tt.wantSources, extractor.config.sourcePriority); diff != "" {
					t.Fatalf("source priority mismatch (-want +got):\n%s", diff)
				}
				return
			}

			got := errorTextStateOf(err, tt.wantErrText)
			want := errorTextState{HasErr: true, ContainsText: true}
			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("New() error mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestWithTrustedPrivateProxyRanges_AddsExpectedCIDRs(t *testing.T) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = PrivateProxyPrefixes()

	extractor, err := New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got := snapshotConfig(extractor.config).TrustedProxyCIDRs
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("trusted CIDRs mismatch (-want +got):\n%s", diff)
	}
}

func TestProxyPrefixesFromAddrs(t *testing.T) {
	t.Run("valid addrs", func(t *testing.T) {
		prefixes, err := ProxyPrefixesFromAddrs(
			netip.MustParseAddr("1.1.1.1"),
			netip.MustParseAddr("2001:db8::1"),
		)
		if err != nil {
			t.Fatalf("ProxyPrefixesFromAddrs() error = %v", err)
		}

		want := []string{"1.1.1.1/32", "2001:db8::1/128"}
		if diff := cmp.Diff(want, cidrStrings(prefixes)); diff != "" {
			t.Fatalf("prefixes mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("invalid addr", func(t *testing.T) {
		_, err := ProxyPrefixesFromAddrs(netip.Addr{})
		if err == nil {
			t.Fatal("ProxyPrefixesFromAddrs() error = nil, want non-nil")
		}
		if !strings.Contains(err.Error(), "invalid proxy address") {
			t.Fatalf("ProxyPrefixesFromAddrs() error = %q, want containing %q", err.Error(), "invalid proxy address")
		}
	})
}

func TestStringers(t *testing.T) {
	tests := []struct {
		name string
		got  string
		want string
	}{
		{name: "rightmost selection", got: RightmostUntrustedIP.String(), want: "rightmost_untrusted"},
		{name: "leftmost selection", got: LeftmostUntrustedIP.String(), want: "leftmost_untrusted"},
		{name: "unknown selection", got: ChainSelection(999).String(), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.got); diff != "" {
				t.Fatalf("string mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

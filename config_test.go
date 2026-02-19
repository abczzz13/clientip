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
	SecurityMode          SecurityMode
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
		SecurityMode:          cfg.securityMode,
		DebugMode:             cfg.debugMode,
		SourcePriority:        cloneStrings(cfg.sourcePriority),
	}
}

func cidrStrings(prefixes []netip.Prefix) []string {
	values := make([]string, len(prefixes))
	for i, prefix := range prefixes {
		values[i] = prefix.String()
	}
	return values
}

func TestNew_ConfigScenarios(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		want        configSnapshot
		wantErrText string
	}{
		{
			name: "default",
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
			name: "configured options",
			opts: []Option{
				TrustProxyPrefixes(
					netip.MustParsePrefix("10.0.0.0/8"),
					netip.MustParsePrefix("172.16.0.0/12"),
				),
				MinTrustedProxies(1),
				MaxTrustedProxies(3),
				AllowPrivateIPs(true),
				AllowReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24")),
				MaxChainLength(42),
				WithChainSelection(LeftmostUntrustedIP),
				WithSecurityMode(SecurityModeLax),
				WithDebugInfo(true),
				Priority(SourceXForwardedFor, SourceRemoteAddr),
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12"},
				MinTrustedProxies:     1,
				MaxTrustedProxies:     3,
				AllowPrivateIPs:       true,
				AllowReservedPrefixes: []string{"198.51.100.0/24"},
				MaxChainLength:        42,
				ChainSelection:        LeftmostUntrustedIP,
				SecurityMode:          SecurityModeLax,
				DebugMode:             true,
				SourcePriority:        []string{SourceXForwardedFor, SourceRemoteAddr},
			},
		},
		{
			name: "merge option fragments",
			opts: []Option{
				TrustLoopbackProxy(),
				Priority(SourceXForwardedFor, SourceRemoteAddr),
				WithSecurityMode(SecurityModeLax),
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"127.0.0.0/8", "::1/128"},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				SecurityMode:          SecurityModeLax,
				DebugMode:             false,
				SourcePriority:        []string{SourceXForwardedFor, SourceRemoteAddr},
			},
		},
		{
			name: "merge trusted proxy prefixes",
			opts: []Option{
				TrustProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
				TrustProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("172.16.0.0/12")),
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"10.0.0.0/8", "172.16.0.0/12"},
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
			name: "merge reserved client prefixes",
			opts: []Option{
				AllowReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24")),
				AllowReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("203.0.113.0/24")),
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{"198.51.100.0/24", "203.0.113.0/24"},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				SecurityMode:          SecurityModeStrict,
				DebugMode:             false,
				SourcePriority:        []string{SourceRemoteAddr},
			},
		},
		{
			name:        "invalid trusted prefix helper",
			opts:        []Option{TrustProxyPrefixes(netip.Prefix{})},
			wantErrText: "invalid trusted proxy prefix",
		},
		{
			name:        "invalid allow reserved prefix helper",
			opts:        []Option{AllowReservedClientPrefixes(netip.Prefix{})},
			wantErrText: "invalid reserved client prefix",
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
				t.Fatalf("config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestNew_InvalidOptions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	tests := []struct {
		name        string
		opts        []Option
		wantErrText string
	}{
		{
			name:        "min exceeds max",
			opts:        []Option{TrustProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8")), MinTrustedProxies(5), MaxTrustedProxies(2)},
			wantErrText: "minTrustedProxies",
		},
		{
			name:        "header source without trusted proxies",
			opts:        []Option{Priority(SourceXForwardedFor)},
			wantErrText: "header-based sources require trusted proxy prefixes",
		},
		{
			name:        "invalid chain selection",
			opts:        []Option{WithChainSelection(ChainSelection(999))},
			wantErrText: "invalid chain selection",
		},
		{
			name:        "invalid security mode",
			opts:        []Option{WithSecurityMode(SecurityMode(999))},
			wantErrText: "invalid security mode",
		},
		{
			name:        "empty explicit source priority",
			opts:        []Option{Priority()},
			wantErrText: "at least one source required",
		},
		{
			name:        "typed nil logger",
			opts:        []Option{WithLogger((*slog.Logger)(nil))},
			wantErrText: "logger cannot be nil",
		},
		{
			name:        "typed nil metrics",
			opts:        []Option{WithMetrics((*testTypedNilMetrics)(nil))},
			wantErrText: "metrics cannot be nil",
		},
		{
			name:        "invalid trust proxy addr helper",
			opts:        []Option{TrustProxyAddrs(netip.Addr{})},
			wantErrText: "invalid proxy address",
		},
		{
			name:        "leftmost without trusted proxies",
			opts:        []Option{Priority(SourceXForwardedFor), WithChainSelection(LeftmostUntrustedIP)},
			wantErrText: "LeftmostUntrustedIP selection requires trusted proxy prefixes",
		},
		{
			name:        "multiple chain sources",
			opts:        []Option{TrustProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8")), Priority(SourceForwarded, SourceXForwardedFor), WithLogger(logger)},
			wantErrText: "priority cannot include both",
		},
		{
			name:        "nil metrics factory",
			opts:        []Option{WithMetricsFactory(nil)},
			wantErrText: "metrics factory cannot be nil",
		},
		{
			name: "typed nil metrics from factory",
			opts: []Option{WithMetricsFactory(func() (Metrics, error) {
				return (*testTypedNilMetrics)(nil), nil
			})},
			wantErrText: "metrics cannot be nil",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if err == nil {
				t.Fatalf("New() error = nil, want containing %q", tt.wantErrText)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("New() error = %q, want containing %q", err.Error(), tt.wantErrText)
			}
		})
	}
}

func TestNew_WithMetricsFactory_Lifecycle(t *testing.T) {
	t.Run("factory not called when configuration invalid", func(t *testing.T) {
		calls := 0

		_, err := New(
			WithMetricsFactory(func() (Metrics, error) {
				calls++
				return noopMetrics{}, nil
			}),
			Priority(SourceXForwardedFor),
		)
		if err == nil {
			t.Fatal("New() error = nil, want non-nil")
		}
		if calls != 0 {
			t.Fatalf("metrics factory calls = %d, want 0", calls)
		}
	})

	t.Run("factory called once when configuration valid", func(t *testing.T) {
		calls := 0

		_, err := New(
			WithMetricsFactory(func() (Metrics, error) {
				calls++
				return noopMetrics{}, nil
			}),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if calls != 1 {
			t.Fatalf("metrics factory calls = %d, want 1", calls)
		}
	})

	t.Run("WithMetrics after factory disables factory", func(t *testing.T) {
		calls := 0

		_, err := New(
			WithMetricsFactory(func() (Metrics, error) {
				calls++
				return noopMetrics{}, nil
			}),
			WithMetrics(noopMetrics{}),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if calls != 0 {
			t.Fatalf("metrics factory calls = %d, want 0", calls)
		}
	})

	t.Run("factory last overrides prior metrics value", func(t *testing.T) {
		calls := 0

		_, err := New(
			WithMetrics((*testTypedNilMetrics)(nil)),
			WithMetricsFactory(func() (Metrics, error) {
				calls++
				return noopMetrics{}, nil
			}),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		if calls != 1 {
			t.Fatalf("metrics factory calls = %d, want 1", calls)
		}
	})
}

func TestConfig_WithOverrides(t *testing.T) {
	base, err := configFromOptions(
		TrustLoopbackProxy(),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("configFromOptions() error = %v", err)
	}

	tests := []struct {
		name        string
		overrides   []OverrideOptions
		want        configSnapshot
		wantErrText string
	}{
		{
			name: "last wins on scalar",
			overrides: []OverrideOptions{
				{SecurityMode: Set(SecurityModeLax)},
				{SecurityMode: Set(SecurityModeStrict)},
			},
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
			name: "override source priority",
			overrides: []OverrideOptions{
				{SourcePriority: Set([]string{SourceRemoteAddr})},
			},
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
				SourcePriority:        []string{SourceRemoteAddr},
			},
		},
		{
			name: "override trusted prefixes normalizes and dedupes",
			overrides: []OverrideOptions{
				{TrustedProxyPrefixes: Set([]netip.Prefix{
					netip.MustParsePrefix("10.0.0.1/8"),
					netip.MustParsePrefix("10.0.0.2/8"),
				})},
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"10.0.0.0/8"},
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
			name: "override reserved allowlist",
			overrides: []OverrideOptions{
				{AllowReservedClientPrefixes: Set([]netip.Prefix{
					netip.MustParsePrefix("198.51.100.10/24"),
					netip.MustParsePrefix("198.51.100.0/24"),
				})},
			},
			want: configSnapshot{
				TrustedProxyCIDRs:     []string{"127.0.0.0/8", "::1/128"},
				MinTrustedProxies:     0,
				MaxTrustedProxies:     0,
				AllowPrivateIPs:       false,
				AllowReservedPrefixes: []string{"198.51.100.0/24"},
				MaxChainLength:        DefaultMaxChainLength,
				ChainSelection:        RightmostUntrustedIP,
				SecurityMode:          SecurityModeStrict,
				DebugMode:             false,
				SourcePriority:        []string{SourceXForwardedFor, SourceRemoteAddr},
			},
		},
		{
			name: "invalid empty source priority",
			overrides: []OverrideOptions{
				{SourcePriority: Set([]string{})},
			},
			wantErrText: "at least one source required",
		},
		{
			name: "invalid trusted prefix override",
			overrides: []OverrideOptions{
				{TrustedProxyPrefixes: Set([]netip.Prefix{{}})},
			},
			wantErrText: "invalid trusted proxy prefix",
		},
		{
			name: "invalid reserved prefix override",
			overrides: []OverrideOptions{
				{AllowReservedClientPrefixes: Set([]netip.Prefix{{}})},
			},
			wantErrText: "invalid reserved client prefix",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			effective, err := base.withOverrides(tt.overrides...)
			if tt.wantErrText != "" {
				if err == nil {
					t.Fatalf("withOverrides() error = nil, want containing %q", tt.wantErrText)
				}
				if !strings.Contains(err.Error(), tt.wantErrText) {
					t.Fatalf("withOverrides() error = %q, want containing %q", err.Error(), tt.wantErrText)
				}
				return
			}

			if err != nil {
				t.Fatalf("withOverrides() error = %v", err)
			}

			if diff := cmp.Diff(tt.want, snapshotConfig(effective)); diff != "" {
				t.Fatalf("override config mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestConfig_WithOverrides_NoSetValues_ReturnsBase(t *testing.T) {
	base, err := configFromOptions(
		TrustLoopbackProxy(),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("configFromOptions() error = %v", err)
	}

	effective, err := base.withOverrides(
		OverrideOptions{},
		OverrideOptions{},
	)
	if err != nil {
		t.Fatalf("withOverrides() error = %v", err)
	}

	if effective != base {
		t.Fatal("withOverrides() should return original config when no values are set")
	}
}

func TestConfig_WithOverrides_PreservesTrustedProxyMatcherWithoutPrefixOverride(t *testing.T) {
	base, err := configFromOptions(
		TrustProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("configFromOptions() error = %v", err)
	}

	if !base.trustedProxyMatch.initialized {
		t.Fatal("base matcher should be initialized")
	}

	effective, err := base.withOverrides(OverrideOptions{SecurityMode: Set(SecurityModeLax)})
	if err != nil {
		t.Fatalf("withOverrides() error = %v", err)
	}

	if effective == base {
		t.Fatal("withOverrides() should return a cloned config when overrides are set")
	}

	if effective.trustedProxyMatch != base.trustedProxyMatch {
		t.Fatal("trusted proxy matcher should be reused when trusted proxy prefixes are unchanged")
	}
}

func TestConfig_WithOverrides_RebuildsTrustedProxyMatcherWithPrefixOverride(t *testing.T) {
	base, err := configFromOptions(
		TrustProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("configFromOptions() error = %v", err)
	}

	effective, err := base.withOverrides(OverrideOptions{
		TrustedProxyPrefixes: Set([]netip.Prefix{netip.MustParsePrefix("192.168.0.0/16")}),
	})
	if err != nil {
		t.Fatalf("withOverrides() error = %v", err)
	}

	if !effective.trustedProxyMatch.initialized {
		t.Fatal("trusted proxy matcher should be initialized")
	}

	if !effective.trustedProxyMatch.contains(netip.MustParseAddr("192.168.1.2")) {
		t.Fatal("expected overridden matcher to trust new CIDR range")
	}

	if effective.trustedProxyMatch.contains(netip.MustParseAddr("10.1.2.3")) {
		t.Fatal("expected overridden matcher to stop trusting previous CIDR range")
	}
}

func TestNew_InvalidBoundsAndDuplicatePriority(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		wantErrText string
	}{
		{
			name:        "negative min trusted proxies",
			opts:        []Option{MinTrustedProxies(-1)},
			wantErrText: "minTrustedProxies must be >= 0",
		},
		{
			name:        "negative max trusted proxies",
			opts:        []Option{MaxTrustedProxies(-1)},
			wantErrText: "maxTrustedProxies must be >= 0",
		},
		{
			name:        "zero max chain length",
			opts:        []Option{MaxChainLength(0)},
			wantErrText: "maxChainLength must be > 0",
		},
		{
			name:        "negative max chain length",
			opts:        []Option{MaxChainLength(-1)},
			wantErrText: "maxChainLength must be > 0",
		},
		{
			name:        "duplicate source in priority",
			opts:        []Option{Priority(SourceRemoteAddr, SourceRemoteAddr)},
			wantErrText: "duplicate source",
		},
		{
			name:        "duplicate source after canonicalization",
			opts:        []Option{TrustLoopbackProxy(), Priority(SourceXForwardedFor, "X-Forwarded-For")},
			wantErrText: "duplicate source",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			got := errorTextStateOf(err, tt.wantErrText)

			want := errorTextState{
				HasErr:       true,
				ContainsText: true,
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("New() error mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTrustPrivateProxyRanges_AddsExpectedCIDRs(t *testing.T) {
	extractor, err := New(TrustPrivateProxyRanges())
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got := snapshotConfig(extractor.config).TrustedProxyCIDRs
	want := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("trusted CIDRs mismatch (-want +got):\n%s", diff)
	}
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
		{name: "strict mode", got: SecurityModeStrict.String(), want: "strict"},
		{name: "lax mode", got: SecurityModeLax.String(), want: "lax"},
		{name: "unknown mode", got: SecurityMode(999).String(), want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.got); diff != "" {
				t.Fatalf("string mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

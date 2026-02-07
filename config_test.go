package clientip

import (
	"io"
	"log/slog"
	"net/http"
	"net/netip"
	"testing"
)

func TestNew_Success(t *testing.T) {
	tests := []struct {
		name string
		opts []Option
	}{
		{
			name: "default config",
			opts: nil,
		},
		{
			name: "with trusted proxies",
			opts: []Option{
				TrustedProxies([]netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}, 1, 2),
			},
		},
		{
			name: "with allow private IPs",
			opts: []Option{
				AllowPrivateIPs(true),
			},
		},
		{
			name: "with custom chain length",
			opts: []Option{
				MaxChainLength(50),
			},
		},
		{
			name: "with logger",
			opts: []Option{
				WithLogger(slog.New(slog.NewTextHandler(io.Discard, nil))),
			},
		},
		{
			name: "with metrics",
			opts: []Option{
				WithMetrics(newMockMetrics()),
			},
		},
		{
			name: "with priority",
			opts: []Option{
				Priority(SourceXForwardedFor, SourceRemoteAddr),
			},
		},
		{
			name: "with rightmost strategy",
			opts: []Option{
				XFFStrategy(RightmostIP),
			},
		},
		{
			name: "with leftmost strategy",
			opts: []Option{
				TrustedCIDRs("10.0.0.0/8"),
				XFFStrategy(LeftmostIP),
			},
		},
		{
			name: "with debug info",
			opts: []Option{
				WithDebugInfo(true),
			},
		},
		{
			name: "with security mode lax",
			opts: []Option{
				WithSecurityMode(SecurityModeLax),
			},
		},
		{
			name: "complex configuration",
			opts: []Option{
				TrustedCIDRs("10.0.0.0/8", "172.16.0.0/12"),
				MinProxies(1),
				MaxProxies(3),
				AllowPrivateIPs(false),
				MaxChainLength(50),
				XFFStrategy(RightmostIP),
				WithDebugInfo(true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, err := New(tt.opts...)
			if err != nil {
				t.Errorf("New() error = %v, want nil", err)
			}
			if extractor == nil {
				t.Error("New() returned nil extractor")
			}
		})
	}
}

func TestNew_Errors(t *testing.T) {
	tests := []struct {
		name        string
		opts        []Option
		wantErrText string
	}{
		{
			name: "min > max proxies",
			opts: []Option{
				TrustedCIDRs("10.0.0.0/8"),
				MinProxies(5),
				MaxProxies(2),
			},
			wantErrText: "minTrustedProxies",
		},
		{
			name: "min proxies without CIDRs",
			opts: []Option{
				MinProxies(1),
			},
			wantErrText: "minTrustedProxies > 0 requires trustedProxyCIDRs",
		},
		{
			name: "negative min proxies",
			opts: []Option{
				MinProxies(-1),
			},
			wantErrText: "minTrustedProxies must be >= 0",
		},
		{
			name: "negative max proxies",
			opts: []Option{
				MaxProxies(-1),
			},
			wantErrText: "maxTrustedProxies must be >= 0",
		},
		{
			name: "zero max chain length",
			opts: []Option{
				MaxChainLength(0),
			},
			wantErrText: "maxChainLength must be > 0",
		},
		{
			name: "negative max chain length",
			opts: []Option{
				MaxChainLength(-1),
			},
			wantErrText: "maxChainLength must be > 0",
		},
		{
			name: "nil logger",
			opts: []Option{
				WithLogger(nil),
			},
			wantErrText: "logger cannot be nil",
		},
		{
			name: "typed nil logger",
			opts: []Option{
				WithLogger((*slog.Logger)(nil)),
			},
			wantErrText: "logger cannot be nil",
		},
		{
			name: "nil metrics",
			opts: []Option{
				WithMetrics(nil),
			},
			wantErrText: "metrics cannot be nil",
		},
		{
			name: "empty priority",
			opts: []Option{
				Priority(),
			},
			wantErrText: "at least one source required",
		},
		{
			name: "invalid strategy",
			opts: []Option{
				XFFStrategy(Strategy(999)),
			},
			wantErrText: "invalid XFF strategy",
		},
		{
			name: "invalid security mode",
			opts: []Option{
				WithSecurityMode(SecurityMode(999)),
			},
			wantErrText: "invalid security mode",
		},
		{
			name: "leftmost without CIDRs",
			opts: []Option{
				XFFStrategy(LeftmostIP),
			},
			wantErrText: "LeftmostIP strategy requires trustedProxyCIDRs",
		},
		{
			name: "invalid CIDR",
			opts: []Option{
				TrustedCIDRs("not-a-cidr"),
			},
			wantErrText: "invalid CIDR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(tt.opts...)
			if err == nil {
				t.Error("New() error = nil, want error")
			} else if !contains(err.Error(), tt.wantErrText) {
				t.Errorf("New() error = %q, want to contain %q", err.Error(), tt.wantErrText)
			}
		})
	}
}

func TestStrategy_String(t *testing.T) {
	tests := []struct {
		strategy Strategy
		want     string
	}{
		{RightmostIP, "rightmost"},
		{LeftmostIP, "leftmost"},
		{Strategy(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.strategy.String()
			if got != tt.want {
				t.Errorf("Strategy.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSecurityMode_String(t *testing.T) {
	tests := []struct {
		mode SecurityMode
		want string
	}{
		{SecurityModeStrict, "strict"},
		{SecurityModeLax, "lax"},
		{SecurityMode(999), "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			got := tt.mode.String()
			if got != tt.want {
				t.Errorf("SecurityMode.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *Config
		wantErr bool
	}{
		{
			name: "valid default config",
			cfg:  defaultConfig(),
		},
		{
			name: "valid with trusted proxies",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = 1
				c.maxTrustedProxies = 3
				c.trustedProxyCIDRs = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
				}
				return c
			}(),
		},
		{
			name: "min = max is valid",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = 2
				c.maxTrustedProxies = 2
				c.trustedProxyCIDRs = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
				}
				return c
			}(),
		},
		{
			name: "min = 0, max > 0 is valid",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = 0
				c.maxTrustedProxies = 3
				c.trustedProxyCIDRs = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
				}
				return c
			}(),
		},
		{
			name: "min > 0, max = 0 is valid",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = 1
				c.maxTrustedProxies = 0
				c.trustedProxyCIDRs = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
				}
				return c
			}(),
		},
		{
			name: "min > max should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = 5
				c.maxTrustedProxies = 2
				c.trustedProxyCIDRs = []netip.Prefix{
					netip.MustParsePrefix("10.0.0.0/8"),
				}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "min > 0 without CIDRs should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = 1
				c.maxTrustedProxies = 3
				c.trustedProxyCIDRs = []netip.Prefix{}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "negative min should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.minTrustedProxies = -1
				return c
			}(),
			wantErr: true,
		},
		{
			name: "negative max should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.maxTrustedProxies = -1
				return c
			}(),
			wantErr: true,
		},
		{
			name: "zero max chain length should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.maxChainLength = 0
				return c
			}(),
			wantErr: true,
		},
		{
			name: "negative max chain length should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.maxChainLength = -1
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid strategy should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.forwardedForStrategy = Strategy(999)
				return c
			}(),
			wantErr: true,
		},
		{
			name: "invalid security mode should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.securityMode = SecurityMode(999)
				return c
			}(),
			wantErr: true,
		},
		{
			name: "leftmost without CIDRs should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.forwardedForStrategy = LeftmostIP
				c.trustedProxyCIDRs = []netip.Prefix{}
				return c
			}(),
			wantErr: true,
		},
		{
			name: "nil logger should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.logger = nil
				return c
			}(),
			wantErr: true,
		},
		{
			name: "typed nil logger should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.logger = (*slog.Logger)(nil)
				return c
			}(),
			wantErr: true,
		},
		{
			name: "nil metrics should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.metrics = nil
				return c
			}(),
			wantErr: true,
		},
		{
			name: "empty source priority should fail",
			cfg: func() *Config {
				c := defaultConfig()
				c.sourcePriority = []string{}
				return c
			}(),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Config.validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestTrustedProxies(t *testing.T) {
	cidrs := []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}

	t.Run("sets all fields", func(t *testing.T) {
		cfg := defaultConfig()
		opt := TrustedProxies(cidrs, 1, 3)
		err := opt(cfg)
		if err != nil {
			t.Fatalf("TrustedProxies() error = %v", err)
		}

		if len(cfg.trustedProxyCIDRs) != 1 {
			t.Errorf("trustedProxyCIDRs length = %d, want 1", len(cfg.trustedProxyCIDRs))
		}
		if cfg.minTrustedProxies != 1 {
			t.Errorf("minTrustedProxies = %d, want 1", cfg.minTrustedProxies)
		}
		if cfg.maxTrustedProxies != 3 {
			t.Errorf("maxTrustedProxies = %d, want 3", cfg.maxTrustedProxies)
		}
	})
}

func TestTrustedCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		wantErr bool
		wantLen int
	}{
		{
			name:    "valid single CIDR",
			cidrs:   []string{"10.0.0.0/8"},
			wantLen: 1,
		},
		{
			name:    "valid multiple CIDRs",
			cidrs:   []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			wantLen: 3,
		},
		{
			name:    "valid IPv6 CIDR",
			cidrs:   []string{"2001:db8::/32"},
			wantLen: 1,
		},
		{
			name:    "mixed IPv4 and IPv6",
			cidrs:   []string{"10.0.0.0/8", "2001:db8::/32"},
			wantLen: 2,
		},
		{
			name:    "invalid CIDR",
			cidrs:   []string{"not-a-cidr"},
			wantErr: true,
		},
		{
			name:    "invalid among valid",
			cidrs:   []string{"10.0.0.0/8", "invalid", "192.168.0.0/16"},
			wantErr: true,
		},
		{
			name:    "empty list",
			cidrs:   []string{},
			wantLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			opt := TrustedCIDRs(tt.cidrs...)
			err := opt(cfg)

			if (err != nil) != tt.wantErr {
				t.Errorf("TrustedCIDRs() error = %v, wantErr %v", err, tt.wantErr)
			}

			if !tt.wantErr && len(cfg.trustedProxyCIDRs) != tt.wantLen {
				t.Errorf("trustedProxyCIDRs length = %d, want %d", len(cfg.trustedProxyCIDRs), tt.wantLen)
			}
		})
	}
}

func TestMinMaxProxies(t *testing.T) {
	t.Run("MinProxies", func(t *testing.T) {
		cfg := defaultConfig()
		opt := MinProxies(5)
		_ = opt(cfg)

		if cfg.minTrustedProxies != 5 {
			t.Errorf("minTrustedProxies = %d, want 5", cfg.minTrustedProxies)
		}
	})

	t.Run("MaxProxies", func(t *testing.T) {
		cfg := defaultConfig()
		opt := MaxProxies(10)
		_ = opt(cfg)

		if cfg.maxTrustedProxies != 10 {
			t.Errorf("maxTrustedProxies = %d, want 10", cfg.maxTrustedProxies)
		}
	})
}

func TestAllowPrivateIPs(t *testing.T) {
	tests := []struct {
		name  string
		allow bool
	}{
		{"allow true", true},
		{"allow false", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			opt := AllowPrivateIPs(tt.allow)
			_ = opt(cfg)

			if cfg.allowPrivateIPs != tt.allow {
				t.Errorf("allowPrivateIPs = %v, want %v", cfg.allowPrivateIPs, tt.allow)
			}
		})
	}
}

func TestMaxChainLength_Option(t *testing.T) {
	cfg := defaultConfig()
	opt := MaxChainLength(50)
	_ = opt(cfg)

	if cfg.maxChainLength != 50 {
		t.Errorf("maxChainLength = %d, want 50", cfg.maxChainLength)
	}
}

func TestXFFStrategy_Option(t *testing.T) {
	tests := []struct {
		name     string
		strategy Strategy
	}{
		{"rightmost", RightmostIP},
		{"leftmost", LeftmostIP},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			opt := XFFStrategy(tt.strategy)
			_ = opt(cfg)

			if cfg.forwardedForStrategy != tt.strategy {
				t.Errorf("forwardedForStrategy = %v, want %v", cfg.forwardedForStrategy, tt.strategy)
			}
		})
	}
}

func TestWithDebugInfo_Option(t *testing.T) {
	tests := []struct {
		name   string
		enable bool
	}{
		{"enabled", true},
		{"disabled", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			opt := WithDebugInfo(tt.enable)
			_ = opt(cfg)

			if cfg.debugMode != tt.enable {
				t.Errorf("debugMode = %v, want %v", cfg.debugMode, tt.enable)
			}
		})
	}
}

func TestWithSecurityMode_Option(t *testing.T) {
	tests := []struct {
		name string
		mode SecurityMode
	}{
		{"strict", SecurityModeStrict},
		{"lax", SecurityModeLax},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			opt := WithSecurityMode(tt.mode)
			_ = opt(cfg)

			if cfg.securityMode != tt.mode {
				t.Errorf("securityMode = %v, want %v", cfg.securityMode, tt.mode)
			}
		})
	}
}

func TestWithLogger_Option(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	cfg := defaultConfig()
	opt := WithLogger(logger)
	_ = opt(cfg)

	if cfg.logger != logger {
		t.Error("logger not set correctly")
	}
}

func TestWithMetrics_Option(t *testing.T) {
	metrics := newMockMetrics()
	cfg := defaultConfig()
	opt := WithMetrics(metrics)
	_ = opt(cfg)

	if cfg.metrics != metrics {
		t.Error("metrics not set correctly")
	}
}

func TestMetricsOptions_Precedence_LastWins(t *testing.T) {
	t.Run("last WithMetrics option wins", func(t *testing.T) {
		first := newMockMetrics()
		second := newMockMetrics()

		extractor, err := New(
			WithMetrics(first),
			WithMetrics(second),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "1.1.1.1:12345",
			Header:     make(http.Header),
		}
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			t.Fatalf("ExtractIP() error = %v", result.Err)
		}

		if got := first.getSuccessCount(SourceRemoteAddr); got != 0 {
			t.Fatalf("first metrics success count = %d, want 0", got)
		}
		if got := second.getSuccessCount(SourceRemoteAddr); got != 1 {
			t.Fatalf("second metrics success count = %d, want 1", got)
		}
	})
}

func TestPriority_Option(t *testing.T) {
	t.Run("sets custom priority", func(t *testing.T) {
		cfg := defaultConfig()
		opt := Priority(SourceXForwardedFor, SourceRemoteAddr)
		_ = opt(cfg)

		if len(cfg.sourcePriority) != 2 {
			t.Errorf("sourcePriority length = %d, want 2", len(cfg.sourcePriority))
		}
	})

	t.Run("single source", func(t *testing.T) {
		cfg := defaultConfig()
		opt := Priority(SourceXForwardedFor)
		_ = opt(cfg)

		if len(cfg.sourcePriority) != 1 {
			t.Errorf("sourcePriority length = %d, want 1", len(cfg.sourcePriority))
		}
	})

	t.Run("with custom header", func(t *testing.T) {
		cfg := defaultConfig()
		opt := Priority("CF-Connecting-IP", SourceXForwardedFor)
		_ = opt(cfg)

		if len(cfg.sourcePriority) != 2 {
			t.Errorf("sourcePriority length = %d, want 2", len(cfg.sourcePriority))
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := defaultConfig()

	t.Run("has reasonable defaults", func(t *testing.T) {
		if cfg.minTrustedProxies != 0 {
			t.Errorf("minTrustedProxies = %d, want 0", cfg.minTrustedProxies)
		}
		if cfg.maxTrustedProxies != 0 {
			t.Errorf("maxTrustedProxies = %d, want 0", cfg.maxTrustedProxies)
		}
		if cfg.allowPrivateIPs != false {
			t.Errorf("allowPrivateIPs = %v, want false", cfg.allowPrivateIPs)
		}
		if cfg.maxChainLength != DefaultMaxChainLength {
			t.Errorf("maxChainLength = %d, want %d", cfg.maxChainLength, DefaultMaxChainLength)
		}
		if cfg.forwardedForStrategy != RightmostIP {
			t.Errorf("forwardedForStrategy = %v, want RightmostIP", cfg.forwardedForStrategy)
		}
		if cfg.securityMode != SecurityModeStrict {
			t.Errorf("securityMode = %v, want SecurityModeStrict", cfg.securityMode)
		}
		if cfg.logger == nil {
			t.Error("logger is nil")
		}
		if cfg.metrics == nil {
			t.Error("metrics is nil")
		}
		if len(cfg.sourcePriority) != 3 {
			t.Errorf("sourcePriority length = %d, want 3", len(cfg.sourcePriority))
		}
	})

	t.Run("validates successfully", func(t *testing.T) {
		if err := cfg.validate(); err != nil {
			t.Errorf("defaultConfig().validate() error = %v", err)
		}
	})
}

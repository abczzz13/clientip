package clientip

import (
	"fmt"
	"io"
	"log/slog"
	"net/netip"
)

const (
	// DefaultMaxChainLength is the maximum number of IPs allowed in an X-Forwarded-For chain.
	// This prevents DoS attacks using extremely long header values that could cause excessive
	// memory allocation or CPU usage during parsing. 100 is chosen as a reasonable upper bound
	// that accommodates complex multi-region, multi-CDN setups while still providing protection.
	// Typical proxy chains rarely exceed 5-10 entries.
	DefaultMaxChainLength = 100
)

type Strategy int

const (
	// Start at 1 to avoid zero-value confusion and make invalid strategies explicit
	RightmostIP Strategy = iota + 1
	LeftmostIP
)

func (s Strategy) String() string {
	switch s {
	case RightmostIP:
		return "rightmost"
	case LeftmostIP:
		return "leftmost"
	default:
		return "unknown"
	}
}

func (s Strategy) Valid() bool {
	return s == RightmostIP || s == LeftmostIP
}

type SecurityMode int

const (
	SecurityModeStrict SecurityMode = iota + 1
	SecurityModeLax
)

func (m SecurityMode) String() string {
	switch m {
	case SecurityModeStrict:
		return "strict"
	case SecurityModeLax:
		return "lax"
	default:
		return "unknown"
	}
}

func (m SecurityMode) Valid() bool {
	return m == SecurityModeStrict || m == SecurityModeLax
}

type Config struct {
	trustedProxyCIDRs []netip.Prefix
	minTrustedProxies int
	maxTrustedProxies int

	allowPrivateIPs      bool
	maxChainLength       int
	forwardedForStrategy Strategy
	securityMode         SecurityMode
	debugMode            bool

	sourcePriority []string

	logger  *slog.Logger
	metrics Metrics
}

type Option func(*Config) error

func (c *Config) validate() error {
	if c.minTrustedProxies < 0 {
		return fmt.Errorf("minTrustedProxies must be >= 0, got %d", c.minTrustedProxies)
	}
	if c.maxTrustedProxies < 0 {
		return fmt.Errorf("maxTrustedProxies must be >= 0, got %d", c.maxTrustedProxies)
	}
	if c.maxTrustedProxies > 0 && c.minTrustedProxies > c.maxTrustedProxies {
		return fmt.Errorf("minTrustedProxies (%d) cannot exceed maxTrustedProxies (%d)", c.minTrustedProxies, c.maxTrustedProxies)
	}
	if c.minTrustedProxies > 0 && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("minTrustedProxies > 0 requires trustedProxyCIDRs to be configured for security validation; to skip validation and trust all proxies, use TrustedCIDRs(\"0.0.0.0/0\", \"::/0\")")
	}
	if c.maxChainLength <= 0 {
		return fmt.Errorf("maxChainLength must be > 0, got %d", c.maxChainLength)
	}
	if !c.forwardedForStrategy.Valid() {
		return fmt.Errorf("invalid XFF strategy %d (must be RightmostIP=1 or LeftmostIP=2)", c.forwardedForStrategy)
	}
	if !c.securityMode.Valid() {
		return fmt.Errorf("invalid security mode %d (must be SecurityModeStrict=1 or SecurityModeLax=2)", c.securityMode)
	}
	if c.forwardedForStrategy == LeftmostIP && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("LeftmostIP strategy requires trustedProxyCIDRs to be configured; without CIDR validation, this strategy provides no security benefit over RightmostIP")
	}
	if c.logger == nil {
		return fmt.Errorf("logger cannot be nil")
	}
	if c.metrics == nil {
		return fmt.Errorf("metrics cannot be nil")
	}
	if len(c.sourcePriority) == 0 {
		return fmt.Errorf("at least one source required in priority list")
	}
	return nil
}

func defaultConfig() *Config {
	return &Config{
		minTrustedProxies:    0,
		maxTrustedProxies:    0,
		allowPrivateIPs:      false,
		maxChainLength:       DefaultMaxChainLength,
		forwardedForStrategy: RightmostIP,
		securityMode:         SecurityModeStrict,
		logger:               slog.New(slog.NewTextHandler(io.Discard, nil)),
		metrics:              noopMetrics{},
		sourcePriority: []string{
			SourceXForwardedFor,
			SourceXRealIP,
			SourceRemoteAddr,
		},
	}
}

func TrustedProxies(cidrs []netip.Prefix, min, max int) Option {
	return func(c *Config) error {
		c.trustedProxyCIDRs = cidrs
		c.minTrustedProxies = min
		c.maxTrustedProxies = max
		return nil
	}
}

func TrustedCIDRs(cidrs ...string) Option {
	return func(c *Config) error {
		prefixes, err := ParseCIDRs(cidrs...)
		if err != nil {
			return err
		}
		c.trustedProxyCIDRs = prefixes
		return nil
	}
}

func MinProxies(min int) Option {
	return func(c *Config) error {
		c.minTrustedProxies = min
		return nil
	}
}

func MaxProxies(max int) Option {
	return func(c *Config) error {
		c.maxTrustedProxies = max
		return nil
	}
}

func AllowPrivateIPs(allow bool) Option {
	return func(c *Config) error {
		c.allowPrivateIPs = allow
		return nil
	}
}

func MaxChainLength(max int) Option {
	return func(c *Config) error {
		c.maxChainLength = max
		return nil
	}
}

func WithLogger(logger *slog.Logger) Option {
	return func(c *Config) error {
		c.logger = logger
		return nil
	}
}

func WithMetrics(metrics Metrics) Option {
	return func(c *Config) error {
		c.metrics = metrics
		return nil
	}
}

func Priority(sources ...string) Option {
	return func(c *Config) error {
		if len(sources) == 0 {
			return fmt.Errorf("at least one source required")
		}
		c.sourcePriority = sources
		return nil
	}
}

func XFFStrategy(strategy Strategy) Option {
	return func(c *Config) error {
		c.forwardedForStrategy = strategy
		return nil
	}
}

func WithDebugInfo(enable bool) Option {
	return func(c *Config) error {
		c.debugMode = enable
		return nil
	}
}

func WithSecurityMode(mode SecurityMode) Option {
	return func(c *Config) error {
		c.securityMode = mode
		return nil
	}
}

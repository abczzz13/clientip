package clientip

import (
	"fmt"
	"net/netip"
	"reflect"
	"strings"
)

const (
	// DefaultMaxChainLength is the maximum number of IPs allowed in a proxy
	// chain. This prevents DoS attacks using extremely long header values that
	// could cause excessive memory allocation or CPU usage during parsing. 100
	// is chosen as a reasonable upper bound that accommodates complex
	// multi-region, multi-CDN setups while still providing protection. Typical
	// proxy chains rarely exceed 5-10 entries.
	DefaultMaxChainLength = 100
)

// ChainSelection controls how the client candidate is selected from a parsed
// proxy chain after trusted proxy validation.
type ChainSelection int

const (
	// Start at 1 to avoid zero-value confusion and make invalid selections
	// explicit
	//
	// RightmostUntrustedIP selects the rightmost untrusted address in the chain.
	RightmostUntrustedIP ChainSelection = iota + 1
	// LeftmostUntrustedIP selects the leftmost untrusted address in the chain.
	LeftmostUntrustedIP
)

func (s ChainSelection) String() string {
	switch s {
	case RightmostUntrustedIP:
		return "rightmost_untrusted"
	case LeftmostUntrustedIP:
		return "leftmost_untrusted"
	default:
		return "unknown"
	}
}

func (s ChainSelection) Valid() bool {
	return s == RightmostUntrustedIP || s == LeftmostUntrustedIP
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

	allowPrivateIPs bool
	maxChainLength  int
	chainSelection  ChainSelection
	securityMode    SecurityMode
	debugMode       bool

	sourcePriority []string

	logger  Logger
	metrics Metrics
}

type Option func(*Config) error

func applyOptions(c *Config, opts ...Option) error {
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return err
		}
	}

	return nil
}

var (
	// loopbackProxyCIDRs contains loopback networks used when the app sits
	// behind a reverse proxy running on the same host.
	loopbackProxyCIDRs = []netip.Prefix{
		mustParsePrefix("127.0.0.0/8"),
		mustParsePrefix("::1/128"),
	}

	// privateProxyCIDRs contains private-network ranges commonly used for
	// trusted upstream proxies in VM and internal network deployments.
	privateProxyCIDRs = []netip.Prefix{
		mustParsePrefix("10.0.0.0/8"),
		mustParsePrefix("172.16.0.0/12"),
		mustParsePrefix("192.168.0.0/16"),
		mustParsePrefix("fc00::/7"),
	}
)

func mustParsePrefix(cidr string) netip.Prefix {
	prefix, err := netip.ParsePrefix(cidr)
	if err != nil {
		panic(fmt.Sprintf("invalid built-in CIDR %q: %v", cidr, err))
	}
	return prefix
}

func appendTrustedProxyCIDRs(c *Config, prefixes ...netip.Prefix) {
	if len(prefixes) == 0 {
		return
	}

	merged := make([]netip.Prefix, 0, len(c.trustedProxyCIDRs)+len(prefixes))
	seen := make(map[netip.Prefix]struct{}, len(c.trustedProxyCIDRs)+len(prefixes))

	for _, prefix := range c.trustedProxyCIDRs {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		merged = append(merged, prefix)
	}

	for _, prefix := range prefixes {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		merged = append(merged, prefix)
	}

	c.trustedProxyCIDRs = merged
}

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
	if !c.chainSelection.Valid() {
		return fmt.Errorf("invalid chain selection %d (must be RightmostUntrustedIP=1 or LeftmostUntrustedIP=2)", c.chainSelection)
	}
	if !c.securityMode.Valid() {
		return fmt.Errorf("invalid security mode %d (must be SecurityModeStrict=1 or SecurityModeLax=2)", c.securityMode)
	}
	if len(c.sourcePriority) == 0 {
		return fmt.Errorf("at least one source required in priority list")
	}

	hasHeaderSource, hasChainSource, err := c.validateSourcePriority()
	if err != nil {
		return err
	}

	if hasChainSource && c.chainSelection == LeftmostUntrustedIP && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("LeftmostUntrustedIP selection requires trustedProxyCIDRs to be configured; without CIDR validation, this selection provides no security benefit over RightmostUntrustedIP")
	}

	if hasHeaderSource && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("header-based sources require trusted proxy CIDRs; configure TrustedCIDRs/TrustedProxies or trust helpers such as TrustLoopbackProxy, TrustPrivateProxyRanges, or TrustProxyIP")
	}

	if isNilLogger(c.logger) {
		return fmt.Errorf("logger cannot be nil")
	}
	if isNilMetrics(c.metrics) {
		return fmt.Errorf("metrics cannot be nil")
	}
	return nil
}

func (c *Config) validateSourcePriority() (hasHeaderSource, hasChainSource bool, err error) {
	seen := make(map[string]struct{}, len(c.sourcePriority))
	seenForwarded := false
	seenXFF := false

	for _, sourceName := range c.sourcePriority {
		normalized := NormalizeSourceName(strings.TrimSpace(sourceName))
		if normalized == "" {
			return false, false, fmt.Errorf("source names cannot be empty")
		}

		if _, ok := seen[normalized]; ok {
			return false, false, fmt.Errorf("duplicate source %q in priority list", sourceName)
		}
		seen[normalized] = struct{}{}

		if normalized != SourceRemoteAddr {
			hasHeaderSource = true
		}

		switch normalized {
		case SourceForwarded:
			seenForwarded = true
			hasChainSource = true
		case SourceXForwardedFor:
			seenXFF = true
			hasChainSource = true
		}
	}

	if seenForwarded && seenXFF {
		return false, false, fmt.Errorf("priority cannot include both %q and %q; choose one proxy chain header", SourceForwarded, SourceXForwardedFor)
	}

	return hasHeaderSource, hasChainSource, nil
}

func isNilLogger(logger Logger) bool {
	return isNilInterface(logger)
}

func isNilMetrics(metrics Metrics) bool {
	return isNilInterface(metrics)
}

func isNilInterface(v any) bool {
	if v == nil {
		return true
	}

	rv := reflect.ValueOf(v)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func defaultConfig() *Config {
	return &Config{
		minTrustedProxies: 0,
		maxTrustedProxies: 0,
		allowPrivateIPs:   false,
		maxChainLength:    DefaultMaxChainLength,
		chainSelection:    RightmostUntrustedIP,
		securityMode:      SecurityModeStrict,
		logger:            noopLogger{},
		metrics:           noopMetrics{},
		sourcePriority: []string{
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

// TrustLoopbackProxy adds loopback CIDRs to the trusted proxy list.
//
// It trusts 127.0.0.0/8 and ::1/128.
func TrustLoopbackProxy() Option {
	return func(c *Config) error {
		appendTrustedProxyCIDRs(c, loopbackProxyCIDRs...)
		return nil
	}
}

// TrustPrivateProxyRanges adds private network CIDRs to the trusted proxy list.
//
// It trusts 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16, and fc00::/7.
func TrustPrivateProxyRanges() Option {
	return func(c *Config) error {
		appendTrustedProxyCIDRs(c, privateProxyCIDRs...)
		return nil
	}
}

// TrustLocalProxyDefaults adds loopback and private CIDRs to the trusted proxy list.
func TrustLocalProxyDefaults() Option {
	return func(c *Config) error {
		appendTrustedProxyCIDRs(c, loopbackProxyCIDRs...)
		appendTrustedProxyCIDRs(c, privateProxyCIDRs...)
		return nil
	}
}

// TrustProxyIP adds a single proxy host IP to the trusted proxy list.
//
// The IP is normalized and added as an exact host prefix (/32 for IPv4, /128 for IPv6).
func TrustProxyIP(ip string) Option {
	return func(c *Config) error {
		parsedIP := parseIP(ip)
		if !parsedIP.IsValid() {
			return fmt.Errorf("invalid proxy IP %q", ip)
		}

		parsedIP = normalizeIP(parsedIP)
		appendTrustedProxyCIDRs(c, netip.PrefixFrom(parsedIP, parsedIP.BitLen()))
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

func WithLogger(logger Logger) Option {
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

		resolvedSources := make([]string, len(sources))
		for i, source := range sources {
			trimmedSource := strings.TrimSpace(source)
			if trimmedSource == "" {
				return fmt.Errorf("source names cannot be empty")
			}
			resolvedSources[i] = canonicalSourceName(trimmedSource)
		}

		c.sourcePriority = resolvedSources
		return nil
	}
}

// WithChainSelection configures how to choose the client candidate from
// Forwarded/X-Forwarded-For chains.
func WithChainSelection(selection ChainSelection) Option {
	return func(c *Config) error {
		c.chainSelection = selection
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

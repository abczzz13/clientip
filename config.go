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
	// explicit.
	//
	// RightmostUntrustedIP selects the rightmost untrusted address in the chain.
	RightmostUntrustedIP ChainSelection = iota + 1
	// LeftmostUntrustedIP selects the leftmost untrusted address in the chain.
	LeftmostUntrustedIP
)

// String returns the canonical text representation of s.
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

// valid reports whether s is a supported chain-selection mode.
func (s ChainSelection) valid() bool {
	return s == RightmostUntrustedIP || s == LeftmostUntrustedIP
}

// SecurityMode controls fallback behavior after security-significant errors.
type SecurityMode int

const (
	// SecurityModeStrict fails closed and stops on security-significant errors.
	SecurityModeStrict SecurityMode = iota + 1
	// SecurityModeLax allows fallback to lower-priority sources after such errors.
	SecurityModeLax
)

// String returns the canonical text representation of m.
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

// valid reports whether m is a supported security mode.
func (m SecurityMode) valid() bool {
	return m == SecurityModeStrict || m == SecurityModeLax
}

// Option configures an Extractor.
//
// Construct options using package-provided option builder functions.
type Option func(*config) error

// SetValue represents an optional per-call override value.
//
// Use Set(v) to mark an override as explicitly provided.
type SetValue[T any] struct {
	v   T
	set bool
}

// Set marks a value as explicitly set for OverrideOptions.
func Set[T any](value T) SetValue[T] {
	return SetValue[T]{v: value, set: true}
}

// isSet reports whether a value was explicitly provided.
func (s SetValue[T]) isSet() bool {
	return s.set
}

// value returns the stored value.
func (s SetValue[T]) value() T {
	return s.v
}

// OverrideOptions applies per-call policy overrides.
//
// Only policy-related fields are overrideable. Logger and Metrics remain fixed
// at extractor construction time.
type OverrideOptions struct {
	TrustedProxyCIDRs SetValue[[]netip.Prefix]
	MinTrustedProxies SetValue[int]
	MaxTrustedProxies SetValue[int]

	AllowPrivateIPs SetValue[bool]
	MaxChainLength  SetValue[int]
	ChainSelection  SetValue[ChainSelection]
	SecurityMode    SetValue[SecurityMode]
	DebugInfo       SetValue[bool]

	SourcePriority SetValue[[]string]
}

func (o OverrideOptions) hasSetValues() bool {
	return o.TrustedProxyCIDRs.isSet() ||
		o.MinTrustedProxies.isSet() ||
		o.MaxTrustedProxies.isSet() ||
		o.AllowPrivateIPs.isSet() ||
		o.MaxChainLength.isSet() ||
		o.ChainSelection.isSet() ||
		o.SecurityMode.isSet() ||
		o.DebugInfo.isSet() ||
		o.SourcePriority.isSet()
}

// config holds extractor configuration state.
//
// It is mutated by Option functions during construction and override merging.
type config struct {
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

	metricsFactory    func() (Metrics, error)
	useMetricsFactory bool
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

func canonicalizeSourceNames(sources []string) []string {
	resolved := make([]string, len(sources))
	for i, source := range sources {
		resolved[i] = canonicalSourceName(strings.TrimSpace(source))
	}
	return resolved
}

func clonePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	if prefixes == nil {
		return nil
	}
	cloned := make([]netip.Prefix, len(prefixes))
	copy(cloned, prefixes)
	return cloned
}

func cloneStrings(values []string) []string {
	if values == nil {
		return nil
	}
	cloned := make([]string, len(values))
	copy(cloned, values)
	return cloned
}

func appendTrustedProxyCIDRs(c *config, prefixes ...netip.Prefix) {
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

func defaultConfig() *config {
	return &config{
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

func applyOptions(c *config, opts ...Option) error {
	for _, opt := range opts {
		if err := opt(c); err != nil {
			return err
		}
	}

	return nil
}

func configFromOptions(opts ...Option) (*config, error) {
	cfg := defaultConfig()

	if err := applyOptions(cfg, opts...); err != nil {
		return nil, err
	}

	appendTrustedProxyCIDRs(cfg, cfg.trustedProxyCIDRs...)

	if cfg.useMetricsFactory {
		if cfg.metricsFactory == nil {
			return nil, fmt.Errorf("metrics factory cannot be nil")
		}
	}

	validationConfig := cfg
	if cfg.useMetricsFactory {
		validationConfig = cfg.clone()
		validationConfig.metrics = noopMetrics{}
	}

	if err := validationConfig.validate(); err != nil {
		return nil, err
	}

	if cfg.useMetricsFactory {
		metrics, err := cfg.metricsFactory()
		if err != nil {
			return nil, err
		}
		cfg.metrics = metrics

		if err := cfg.validate(); err != nil {
			return nil, err
		}
	}

	return cfg, nil
}

func (c *config) clone() *config {
	return &config{
		trustedProxyCIDRs: clonePrefixes(c.trustedProxyCIDRs),
		minTrustedProxies: c.minTrustedProxies,
		maxTrustedProxies: c.maxTrustedProxies,
		allowPrivateIPs:   c.allowPrivateIPs,
		maxChainLength:    c.maxChainLength,
		chainSelection:    c.chainSelection,
		securityMode:      c.securityMode,
		debugMode:         c.debugMode,
		sourcePriority:    cloneStrings(c.sourcePriority),
		logger:            c.logger,
		metrics:           c.metrics,
		metricsFactory:    c.metricsFactory,
		useMetricsFactory: c.useMetricsFactory,
	}
}

func (c *config) withOverrides(overrides ...OverrideOptions) (*config, error) {
	if len(overrides) == 0 {
		return c, nil
	}

	hasOverrides := false

	for _, override := range overrides {
		if override.hasSetValues() {
			hasOverrides = true
			break
		}
	}

	if !hasOverrides {
		return c, nil
	}

	effective := c.clone()

	for _, override := range overrides {
		if !override.hasSetValues() {
			continue
		}

		if override.TrustedProxyCIDRs.isSet() {
			effective.trustedProxyCIDRs = clonePrefixes(override.TrustedProxyCIDRs.value())
		}
		if override.MinTrustedProxies.isSet() {
			effective.minTrustedProxies = override.MinTrustedProxies.value()
		}
		if override.MaxTrustedProxies.isSet() {
			effective.maxTrustedProxies = override.MaxTrustedProxies.value()
		}

		if override.AllowPrivateIPs.isSet() {
			effective.allowPrivateIPs = override.AllowPrivateIPs.value()
		}
		if override.MaxChainLength.isSet() {
			effective.maxChainLength = override.MaxChainLength.value()
		}
		if override.ChainSelection.isSet() {
			effective.chainSelection = override.ChainSelection.value()
		}
		if override.SecurityMode.isSet() {
			effective.securityMode = override.SecurityMode.value()
		}
		if override.DebugInfo.isSet() {
			effective.debugMode = override.DebugInfo.value()
		}

		if override.SourcePriority.isSet() {
			effective.sourcePriority = canonicalizeSourceNames(cloneStrings(override.SourcePriority.value()))
		}
	}

	appendTrustedProxyCIDRs(effective, effective.trustedProxyCIDRs...)

	if err := effective.validate(); err != nil {
		return nil, err
	}

	return effective, nil
}

func (c *config) validate() error {
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
	if !c.chainSelection.valid() {
		return fmt.Errorf("invalid chain selection %d (must be RightmostUntrustedIP=1 or LeftmostUntrustedIP=2)", c.chainSelection)
	}
	if !c.securityMode.valid() {
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

func (c *config) validateSourcePriority() (hasHeaderSource, hasChainSource bool, err error) {
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

// TrustedProxies sets trusted proxy CIDRs and proxy-count bounds.
//
// min and max apply to trusted proxies found in chain-header sources.
func TrustedProxies(cidrs []netip.Prefix, min, max int) Option {
	trusted := clonePrefixes(cidrs)

	return func(c *config) error {
		c.trustedProxyCIDRs = clonePrefixes(trusted)
		c.minTrustedProxies = min
		c.maxTrustedProxies = max
		return nil
	}
}

// TrustedCIDRs parses and sets trusted proxy CIDRs.
func TrustedCIDRs(cidrs ...string) Option {
	return func(c *config) error {
		prefixes, err := ParseCIDRs(cidrs...)
		if err != nil {
			return err
		}

		c.trustedProxyCIDRs = prefixes
		return nil
	}
}

// TrustLoopbackProxy adds loopback CIDRs to trusted proxy ranges.
func TrustLoopbackProxy() Option {
	return func(c *config) error {
		appendTrustedProxyCIDRs(c, loopbackProxyCIDRs...)
		return nil
	}
}

// TrustPrivateProxyRanges adds private network CIDRs to trusted proxy ranges.
func TrustPrivateProxyRanges() Option {
	return func(c *config) error {
		appendTrustedProxyCIDRs(c, privateProxyCIDRs...)
		return nil
	}
}

// TrustLocalProxyDefaults adds loopback and private network CIDRs.
func TrustLocalProxyDefaults() Option {
	return func(c *config) error {
		appendTrustedProxyCIDRs(c, loopbackProxyCIDRs...)
		appendTrustedProxyCIDRs(c, privateProxyCIDRs...)
		return nil
	}
}

// TrustProxyIP adds a single trusted proxy host IP.
func TrustProxyIP(ip string) Option {
	return func(c *config) error {
		parsedIP := parseIP(ip)
		if !parsedIP.IsValid() {
			return fmt.Errorf("invalid proxy IP %q", ip)
		}

		parsedIP = normalizeIP(parsedIP)
		appendTrustedProxyCIDRs(c, netip.PrefixFrom(parsedIP, parsedIP.BitLen()))
		return nil
	}
}

// MinProxies sets the minimum trusted proxy count for chain-header sources.
func MinProxies(min int) Option {
	return func(c *config) error {
		c.minTrustedProxies = min
		return nil
	}
}

// MaxProxies sets the maximum trusted proxy count for chain-header sources.
func MaxProxies(max int) Option {
	return func(c *config) error {
		c.maxTrustedProxies = max
		return nil
	}
}

// AllowPrivateIPs configures whether private client IPs are accepted.
func AllowPrivateIPs(allow bool) Option {
	return func(c *config) error {
		c.allowPrivateIPs = allow
		return nil
	}
}

// MaxChainLength sets the maximum number of entries accepted in proxy chains.
func MaxChainLength(max int) Option {
	return func(c *config) error {
		c.maxChainLength = max
		return nil
	}
}

// WithLogger sets the logger implementation used for warning events.
func WithLogger(logger Logger) Option {
	return func(c *config) error {
		c.logger = logger
		return nil
	}
}

// WithMetrics sets a concrete metrics implementation.
//
// If previously configured, a metrics factory is disabled.
func WithMetrics(metrics Metrics) Option {
	return func(c *config) error {
		c.metrics = metrics
		c.metricsFactory = nil
		c.useMetricsFactory = false
		return nil
	}
}

// WithMetricsFactory configures a lazy metrics constructor.
//
// The factory is invoked only for the final winning metrics option after
// option validation succeeds.
func WithMetricsFactory(factory func() (Metrics, error)) Option {
	return func(c *config) error {
		if factory == nil {
			return fmt.Errorf("metrics factory cannot be nil")
		}

		c.metricsFactory = factory
		c.useMetricsFactory = true
		return nil
	}
}

// Priority sets extraction source order.
//
// Source names are canonicalized so built-in aliases resolve to canonical
// constants.
func Priority(sources ...string) Option {
	resolvedSources := canonicalizeSourceNames(cloneStrings(sources))

	return func(c *config) error {
		c.sourcePriority = cloneStrings(resolvedSources)
		return nil
	}
}

// WithChainSelection sets how client candidates are chosen from chain headers.
func WithChainSelection(selection ChainSelection) Option {
	return func(c *config) error {
		c.chainSelection = selection
		return nil
	}
}

// WithDebugInfo controls whether chain-debug metadata is included in results.
func WithDebugInfo(enable bool) Option {
	return func(c *config) error {
		c.debugMode = enable
		return nil
	}
}

// WithSecurityMode sets strict or lax fallback behavior after security errors.
func WithSecurityMode(mode SecurityMode) Option {
	return func(c *config) error {
		c.securityMode = mode
		return nil
	}
}

package clientip

import (
	"fmt"
	"net/netip"
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
	TrustedProxyPrefixes SetValue[[]netip.Prefix]
	MinTrustedProxies    SetValue[int]
	MaxTrustedProxies    SetValue[int]

	AllowPrivateIPs             SetValue[bool]
	AllowReservedClientPrefixes SetValue[[]netip.Prefix]
	MaxChainLength              SetValue[int]
	ChainSelection              SetValue[ChainSelection]
	SecurityMode                SetValue[SecurityMode]
	DebugInfo                   SetValue[bool]

	SourcePriority SetValue[[]string]
}

func (o OverrideOptions) hasSetValues() bool {
	return o.TrustedProxyPrefixes.isSet() ||
		o.MinTrustedProxies.isSet() ||
		o.MaxTrustedProxies.isSet() ||
		o.AllowPrivateIPs.isSet() ||
		o.AllowReservedClientPrefixes.isSet() ||
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
	trustedProxyMatch trustedProxyMatcher
	minTrustedProxies int
	maxTrustedProxies int

	allowPrivateIPs             bool
	allowReservedClientPrefixes []netip.Prefix
	maxChainLength              int
	chainSelection              ChainSelection
	securityMode                SecurityMode
	debugMode                   bool

	sourcePriority   []string
	sourceHeaderKeys []string

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

func cloneAddrs(addrs []netip.Addr) []netip.Addr {
	if addrs == nil {
		return nil
	}
	cloned := make([]netip.Addr, len(addrs))
	copy(cloned, addrs)
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

func normalizePrefixes(prefixes []netip.Prefix, kind string) ([]netip.Prefix, error) {
	normalized := make([]netip.Prefix, 0, len(prefixes))
	for _, prefix := range prefixes {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("invalid %s %q", kind, prefix)
		}
		normalized = append(normalized, prefix.Masked())
	}

	return normalized, nil
}

func normalizeTrustedProxyPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	return normalizePrefixes(prefixes, "trusted proxy prefix")
}

func normalizeReservedClientPrefixes(prefixes []netip.Prefix) ([]netip.Prefix, error) {
	return normalizePrefixes(prefixes, "reserved client prefix")
}

func mergeUniquePrefixes(existing []netip.Prefix, additions ...netip.Prefix) []netip.Prefix {
	if len(existing) == 0 && len(additions) == 0 {
		return nil
	}

	merged := make([]netip.Prefix, 0, len(existing)+len(additions))
	seen := make(map[netip.Prefix]struct{}, len(existing)+len(additions))

	for _, prefix := range existing {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		merged = append(merged, prefix)
	}

	for _, prefix := range additions {
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		merged = append(merged, prefix)
	}

	return merged
}

func appendTrustedProxyCIDRs(c *config, prefixes ...netip.Prefix) {
	if len(prefixes) == 0 {
		return
	}

	c.trustedProxyCIDRs = mergeUniquePrefixes(c.trustedProxyCIDRs, prefixes...)
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

	cfg.sourceHeaderKeys = sourceHeaderKeys(cfg.sourcePriority)

	appendTrustedProxyCIDRs(cfg, cfg.trustedProxyCIDRs...)
	cfg.trustedProxyMatch = buildTrustedProxyMatcher(cfg.trustedProxyCIDRs)

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
		trustedProxyCIDRs:           clonePrefixes(c.trustedProxyCIDRs),
		trustedProxyMatch:           c.trustedProxyMatch,
		minTrustedProxies:           c.minTrustedProxies,
		maxTrustedProxies:           c.maxTrustedProxies,
		allowPrivateIPs:             c.allowPrivateIPs,
		allowReservedClientPrefixes: clonePrefixes(c.allowReservedClientPrefixes),
		maxChainLength:              c.maxChainLength,
		chainSelection:              c.chainSelection,
		securityMode:                c.securityMode,
		debugMode:                   c.debugMode,
		sourcePriority:              cloneStrings(c.sourcePriority),
		sourceHeaderKeys:            cloneStrings(c.sourceHeaderKeys),
		logger:                      c.logger,
		metrics:                     c.metrics,
		metricsFactory:              c.metricsFactory,
		useMetricsFactory:           c.useMetricsFactory,
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
	trustedProxyCIDRsOverridden := false

	for _, override := range overrides {
		if !override.hasSetValues() {
			continue
		}

		if override.TrustedProxyPrefixes.isSet() {
			normalized, err := normalizeTrustedProxyPrefixes(override.TrustedProxyPrefixes.value())
			if err != nil {
				return nil, err
			}

			effective.trustedProxyCIDRs = mergeUniquePrefixes(nil, normalized...)
			trustedProxyCIDRsOverridden = true
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
		if override.AllowReservedClientPrefixes.isSet() {
			normalized, err := normalizeReservedClientPrefixes(override.AllowReservedClientPrefixes.value())
			if err != nil {
				return nil, err
			}

			effective.allowReservedClientPrefixes = mergeUniquePrefixes(nil, normalized...)
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
			effective.sourceHeaderKeys = sourceHeaderKeys(effective.sourcePriority)
		}
	}

	if trustedProxyCIDRsOverridden {
		effective.trustedProxyMatch = buildTrustedProxyMatcher(effective.trustedProxyCIDRs)
	}

	if err := effective.validate(); err != nil {
		return nil, err
	}

	return effective, nil
}

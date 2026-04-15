package clientip

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
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

// Config configures an Extractor.
type Config struct {
	TrustedProxyPrefixes          []netip.Prefix
	MinTrustedProxies             int
	MaxTrustedProxies             int
	AllowPrivateIPs               bool
	AllowedReservedClientPrefixes []netip.Prefix
	MaxChainLength                int
	ChainSelection                ChainSelection
	DebugInfo                     bool
	Sources                       []Source
	Logger                        Logger
	Metrics                       Metrics
}

// DefaultConfig returns the default extractor configuration.
func DefaultConfig() Config {
	return Config{
		MaxChainLength: DefaultMaxChainLength,
		ChainSelection: RightmostUntrustedIP,
		Sources:        []Source{builtinSource(sourceRemoteAddr)},
	}
}

// LoopbackProxyPrefixes returns loopback CIDRs commonly used when the app sits
// behind a reverse proxy on the same host.
func LoopbackProxyPrefixes() []netip.Prefix {
	return clonePrefixes(loopbackProxyCIDRs)
}

// PrivateProxyPrefixes returns private-network CIDRs commonly used for trusted
// upstream proxies in VM and internal network deployments.
func PrivateProxyPrefixes() []netip.Prefix {
	return clonePrefixes(privateProxyCIDRs)
}

// LocalProxyPrefixes returns loopback and private-network proxy CIDRs.
func LocalProxyPrefixes() []netip.Prefix {
	return mergeUniquePrefixes(clonePrefixes(loopbackProxyCIDRs), privateProxyCIDRs...)
}

// ProxyPrefixesFromAddrs converts individual proxy addresses into host-sized
// trusted prefixes.
func ProxyPrefixesFromAddrs(addrs ...netip.Addr) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(addrs))
	for _, addr := range addrs {
		if !addr.IsValid() {
			return nil, fmt.Errorf("invalid proxy address %q", addr)
		}

		addr = normalizeIP(addr)
		prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
	}

	return prefixes, nil
}

// config holds normalized runtime configuration state.
type config struct {
	trustedProxyCIDRs []netip.Prefix
	trustedProxyMatch prefixMatcher
	minTrustedProxies int
	maxTrustedProxies int

	allowPrivateIPs             bool
	allowReservedClientPrefixes []netip.Prefix
	maxChainLength              int
	chainSelection              ChainSelection
	debugMode                   bool

	sourcePriority   []Source
	sourceHeaderKeys []string

	logger  Logger
	metrics Metrics
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
		return fmt.Errorf("minTrustedProxies > 0 requires TrustedProxyPrefixes to be configured for security validation; to skip validation and trust all proxies, set TrustedProxyPrefixes to 0.0.0.0/0 and ::/0")
	}
	if c.maxChainLength <= 0 {
		return fmt.Errorf("maxChainLength must be > 0, got %d", c.maxChainLength)
	}
	if !c.chainSelection.valid() {
		return fmt.Errorf("invalid chain selection %d (must be RightmostUntrustedIP=1 or LeftmostUntrustedIP=2)", c.chainSelection)
	}
	if len(c.sourcePriority) == 0 {
		return fmt.Errorf("at least one source required in priority list")
	}

	hasHeaderSource, hasChainSource, err := c.validateSourcePriority()
	if err != nil {
		return err
	}

	if hasChainSource && c.chainSelection == LeftmostUntrustedIP && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("LeftmostUntrustedIP selection requires trusted proxy prefixes to be configured; without trusted-proxy validation, this selection provides no security benefit over RightmostUntrustedIP")
	}

	if hasHeaderSource && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("header-based sources require trusted proxy prefixes; configure TrustedProxyPrefixes directly or use LoopbackProxyPrefixes, PrivateProxyPrefixes, LocalProxyPrefixes, or ProxyPrefixesFromAddrs")
	}

	if isNilValue(c.logger) {
		return fmt.Errorf("logger cannot be nil")
	}
	if isNilValue(c.metrics) {
		return fmt.Errorf("metrics cannot be nil")
	}
	return nil
}

func (c *config) validateSourcePriority() (hasHeaderSource, hasChainSource bool, err error) {
	seen := make(map[Source]struct{}, len(c.sourcePriority))
	seenForwarded := false
	seenXFF := false

	for _, source := range c.sourcePriority {
		source = canonicalSource(source)
		if !source.valid() {
			return false, false, fmt.Errorf("source names cannot be empty")
		}

		if _, ok := seen[source]; ok {
			return false, false, fmt.Errorf("duplicate source %q in priority list", source)
		}
		seen[source] = struct{}{}

		switch source.kind {
		case sourceStaticFallback:
			return false, false, fmt.Errorf("source %q is resolver-only and cannot be used in Config.Sources", source)
		case sourceForwarded:
			seenForwarded = true
			hasChainSource = true
			hasHeaderSource = true
		case sourceXForwardedFor:
			seenXFF = true
			hasChainSource = true
			hasHeaderSource = true
		case sourceXRealIP, sourceHeader:
			hasHeaderSource = true
		}
	}

	if seenForwarded && seenXFF {
		return false, false, fmt.Errorf("priority cannot include both %q and %q; choose one proxy chain header", builtinSource(sourceForwarded), builtinSource(sourceXForwardedFor))
	}

	return hasHeaderSource, hasChainSource, nil
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

func clonePrefixes(prefixes []netip.Prefix) []netip.Prefix {
	return slices.Clone(prefixes)
}

func cloneSources(values []Source) []Source {
	return slices.Clone(values)
}

func isNilValue(v any) bool {
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

func defaultConfig() *config {
	defaults := DefaultConfig()
	return &config{
		minTrustedProxies: defaults.MinTrustedProxies,
		maxTrustedProxies: defaults.MaxTrustedProxies,
		allowPrivateIPs:   defaults.AllowPrivateIPs,
		maxChainLength:    defaults.MaxChainLength,
		chainSelection:    defaults.ChainSelection,
		logger:            noopLogger{},
		metrics:           noopMetrics{},
		sourcePriority:    cloneSources(defaults.Sources),
	}
}

func configFromPublic(public Config) (*config, error) {
	cfg := defaultConfig()

	if public.TrustedProxyPrefixes != nil {
		normalized, err := normalizeTrustedProxyPrefixes(public.TrustedProxyPrefixes)
		if err != nil {
			return nil, err
		}
		cfg.trustedProxyCIDRs = mergeUniquePrefixes(nil, normalized...)
	}

	if public.AllowedReservedClientPrefixes != nil {
		normalized, err := normalizeReservedClientPrefixes(public.AllowedReservedClientPrefixes)
		if err != nil {
			return nil, err
		}
		cfg.allowReservedClientPrefixes = mergeUniquePrefixes(nil, normalized...)
	}

	if public.MaxChainLength != 0 {
		cfg.maxChainLength = public.MaxChainLength
	}
	if public.ChainSelection != 0 {
		cfg.chainSelection = public.ChainSelection
	}
	if public.Sources != nil {
		cfg.sourcePriority = canonicalizeSources(cloneSources(public.Sources))
	}

	cfg.minTrustedProxies = public.MinTrustedProxies
	cfg.maxTrustedProxies = public.MaxTrustedProxies
	cfg.allowPrivateIPs = public.AllowPrivateIPs
	cfg.debugMode = public.DebugInfo

	if public.Logger != nil {
		cfg.logger = public.Logger
	}
	if public.Metrics != nil {
		cfg.metrics = public.Metrics
	}

	cfg.sourceHeaderKeys = sourceHeaderKeys(cfg.sourcePriority)
	cfg.trustedProxyMatch = newPrefixMatcher(cfg.trustedProxyCIDRs)

	if err := cfg.validate(); err != nil {
		return nil, err
	}

	return cfg, nil
}

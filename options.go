package clientip

import (
	"fmt"
	"net/netip"
)

// TrustProxyPrefixes adds trusted proxy network prefixes.
func TrustProxyPrefixes(prefixes ...netip.Prefix) Option {
	prefixes = clonePrefixes(prefixes)

	return func(c *config) error {
		normalized, err := normalizeTrustedProxyPrefixes(prefixes)
		if err != nil {
			return err
		}

		appendTrustedProxyCIDRs(c, normalized...)
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

// TrustProxyAddrs adds trusted upstream proxy host addresses.
func TrustProxyAddrs(addrs ...netip.Addr) Option {
	addrs = cloneAddrs(addrs)

	return func(c *config) error {
		prefixes := make([]netip.Prefix, 0, len(addrs))
		for _, addr := range addrs {
			if !addr.IsValid() {
				return fmt.Errorf("invalid proxy address %q", addr)
			}

			addr = normalizeIP(addr)
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()))
		}

		appendTrustedProxyCIDRs(c, prefixes...)
		return nil
	}
}

// MinTrustedProxies sets the minimum trusted proxy count for chain-header sources.
func MinTrustedProxies(min int) Option {
	return func(c *config) error {
		c.minTrustedProxies = min
		return nil
	}
}

// MaxTrustedProxies sets the maximum trusted proxy count for chain-header sources.
func MaxTrustedProxies(max int) Option {
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

// AllowReservedClientPrefixes configures reserved client prefixes to explicitly allow.
func AllowReservedClientPrefixes(prefixes ...netip.Prefix) Option {
	prefixes = clonePrefixes(prefixes)

	return func(c *config) error {
		normalized, err := normalizeReservedClientPrefixes(prefixes)
		if err != nil {
			return err
		}

		c.allowReservedClientPrefixes = mergeUniquePrefixes(c.allowReservedClientPrefixes, normalized...)
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

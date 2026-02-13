package clientip

import (
	"fmt"
	"net/netip"
)

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

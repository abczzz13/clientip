package clientip

import (
	"net/netip"
	"slices"
)

// WithCallTrustedProxyPrefixes overrides trusted proxy prefixes for one call.
func WithCallTrustedProxyPrefixes(prefixes ...netip.Prefix) CallOption {
	prefixes = slices.Clone(prefixes)

	return func(c *config) error {
		normalized, err := normalizeTrustedProxyPrefixes(prefixes)
		if err != nil {
			return err
		}

		c.trustedProxyCIDRs = mergeUniquePrefixes(nil, normalized...)
		return nil
	}
}

// WithCallMinTrustedProxies overrides the minimum trusted proxy count for one call.
func WithCallMinTrustedProxies(min int) CallOption {
	return func(c *config) error {
		c.minTrustedProxies = min
		return nil
	}
}

// WithCallMaxTrustedProxies overrides the maximum trusted proxy count for one call.
func WithCallMaxTrustedProxies(max int) CallOption {
	return func(c *config) error {
		c.maxTrustedProxies = max
		return nil
	}
}

// WithCallAllowPrivateIPs overrides private-IP policy for one call.
func WithCallAllowPrivateIPs(allow bool) CallOption {
	return func(c *config) error {
		c.allowPrivateIPs = allow
		return nil
	}
}

// WithCallAllowedReservedClientPrefixes overrides reserved-prefix allowlist for one call.
func WithCallAllowedReservedClientPrefixes(prefixes ...netip.Prefix) CallOption {
	prefixes = slices.Clone(prefixes)

	return func(c *config) error {
		normalized, err := normalizeReservedClientPrefixes(prefixes)
		if err != nil {
			return err
		}

		c.allowReservedClientPrefixes = mergeUniquePrefixes(nil, normalized...)
		return nil
	}
}

// WithCallMaxChainLength overrides max chain length for one call.
func WithCallMaxChainLength(max int) CallOption {
	return func(c *config) error {
		c.maxChainLength = max
		return nil
	}
}

// WithCallChainSelection overrides chain selection mode for one call.
func WithCallChainSelection(selection ChainSelection) CallOption {
	return func(c *config) error {
		c.chainSelection = selection
		return nil
	}
}

// WithCallSecurityMode overrides security mode for one call.
func WithCallSecurityMode(mode SecurityMode) CallOption {
	return func(c *config) error {
		c.securityMode = mode
		return nil
	}
}

// WithCallDebugInfo overrides debug-info output for one call.
func WithCallDebugInfo(enable bool) CallOption {
	return func(c *config) error {
		c.debugMode = enable
		return nil
	}
}

// WithCallSourcePriority overrides source priority for one call.
func WithCallSourcePriority(sources ...Source) CallOption {
	sources = canonicalizeSources(slices.Clone(sources))

	return func(c *config) error {
		c.sourcePriority = slices.Clone(sources)
		return nil
	}
}

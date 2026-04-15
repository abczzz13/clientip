package clientip

import (
	"fmt"
)

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
		return fmt.Errorf("minTrustedProxies > 0 requires trusted proxy prefixes to be configured for security validation; to skip validation and trust all proxies, use WithTrustedProxyPrefixes(netip.MustParsePrefix(\"0.0.0.0/0\"), netip.MustParsePrefix(\"::/0\"))")
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
		return fmt.Errorf("LeftmostUntrustedIP selection requires trusted proxy prefixes to be configured; without trusted-proxy validation, this selection provides no security benefit over RightmostUntrustedIP")
	}

	if hasHeaderSource && len(c.trustedProxyCIDRs) == 0 {
		return fmt.Errorf("header-based sources require trusted proxy prefixes; configure WithTrustedProxyPrefixes or trust helpers such as WithTrustedLoopbackProxy, WithTrustedPrivateProxyRanges, WithTrustedLocalProxyDefaults, or WithTrustedProxyAddrs, or use WithCallTrustedProxyPrefixes for a single extraction")
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

		if source.kind != sourceRemoteAddr {
			hasHeaderSource = true
		}

		switch source.kind {
		case sourceForwarded:
			seenForwarded = true
			hasChainSource = true
		case sourceXForwardedFor:
			seenXFF = true
			hasChainSource = true
		}
	}

	if seenForwarded && seenXFF {
		return false, false, fmt.Errorf("priority cannot include both %q and %q; choose one proxy chain header", builtinSource(sourceForwarded), builtinSource(sourceXForwardedFor))
	}

	return hasHeaderSource, hasChainSource, nil
}

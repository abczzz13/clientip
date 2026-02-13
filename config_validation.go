package clientip

import (
	"fmt"
	"reflect"
	"strings"
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

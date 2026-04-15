package clientip

import "net/netip"

func (e *Extractor) isTrustedProxy(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if e.config.trustedProxyMatch.initialized {
		return e.config.trustedProxyMatch.contains(ip)
	}

	for _, cidr := range e.config.trustedProxyCIDRs {
		if cidr.Contains(ip) {
			return true
		}
	}

	return false
}

func (e *Extractor) validateProxyCount(trustedCount int) error {
	if len(e.config.trustedProxyCIDRs) > 0 && e.config.minTrustedProxies > 0 && trustedCount == 0 {
		e.config.metrics.RecordSecurityEvent(securityEventNoTrustedProxies)
		return ErrNoTrustedProxies
	}

	if e.config.minTrustedProxies > 0 && trustedCount < e.config.minTrustedProxies {
		e.config.metrics.RecordSecurityEvent(securityEventTooFewTrustedProxies)
		return ErrTooFewTrustedProxies
	}

	if e.config.maxTrustedProxies > 0 && trustedCount > e.config.maxTrustedProxies {
		e.config.metrics.RecordSecurityEvent(securityEventTooManyTrustedProxies)
		return ErrTooManyTrustedProxies
	}

	return nil
}

// appendChainPart appends one parsed chain part while enforcing maxChainLength.
func (e *Extractor) appendChainPart(parts []string, part string, source Source) ([]string, error) {
	if len(parts) >= e.config.maxChainLength {
		e.config.metrics.RecordSecurityEvent(securityEventChainTooLong)
		return nil, &ChainTooLongError{
			ExtractionError: ExtractionError{
				Err:    ErrChainTooLong,
				Source: source,
			},
			ChainLength: len(parts) + 1,
			MaxLength:   e.config.maxChainLength,
		}
	}

	return append(parts, part), nil
}

package clientip

import "net/netip"

var (
	reservedClientIPv4Prefixes = []netip.Prefix{
		mustParsePrefix("0.0.0.0/8"),
		mustParsePrefix("100.64.0.0/10"),
		mustParsePrefix("192.0.0.0/24"),
		mustParsePrefix("192.0.2.0/24"),
		mustParsePrefix("198.18.0.0/15"),
		mustParsePrefix("198.51.100.0/24"),
		mustParsePrefix("203.0.113.0/24"),
		mustParsePrefix("240.0.0.0/4"),
	}

	reservedClientIPv6Prefixes = []netip.Prefix{
		mustParsePrefix("64:ff9b::/96"),
		mustParsePrefix("64:ff9b:1::/48"),
		mustParsePrefix("100::/64"),
		mustParsePrefix("2001:2::/48"),
		mustParsePrefix("2001:db8::/32"),
		mustParsePrefix("2001:20::/28"),
	}
)

func (e *Extractor) isPlausibleClientIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		e.config.metrics.RecordSecurityEvent(securityEventInvalidIP)
		return false
	}

	// Check for reserved/special-use ranges that should never be client IPs
	if isReservedIP(ip) && !e.isAllowlistedReservedClientIP(ip) {
		e.config.metrics.RecordSecurityEvent(securityEventReservedIP)
		return false
	}

	if !e.config.allowPrivateIPs && ip.IsPrivate() {
		e.config.metrics.RecordSecurityEvent(securityEventPrivateIP)
		return false
	}

	return true
}

func (e *Extractor) isAllowlistedReservedClientIP(ip netip.Addr) bool {
	if len(e.config.allowReservedClientPrefixes) == 0 || !ip.IsValid() {
		return false
	}

	ip = normalizeIP(ip)

	for _, prefix := range e.config.allowReservedClientPrefixes {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

// isReservedIP checks if an IP is in a reserved or special-use range that
// should never appear as a real client IP address.
func isReservedIP(ip netip.Addr) bool {
	if !ip.IsValid() {
		return false
	}

	ip = normalizeIP(ip)

	prefixes := reservedClientIPv6Prefixes
	if ip.Is4() {
		prefixes = reservedClientIPv4Prefixes
	}

	for _, prefix := range prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

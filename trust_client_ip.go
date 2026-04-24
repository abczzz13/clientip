package clientip

import "net/netip"

type clientIPPolicy struct {
	AllowPrivateIPs             bool
	AllowReservedClientPrefixes []netip.Prefix
}

type clientIPDisposition int

const (
	clientIPInvalid clientIPDisposition = iota
	clientIPValid
	clientIPReserved
	clientIPPrivate
)

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

// ipv4SpecialFirstOctet marks first octets that appear in any special IPv4 range
// (private, reserved, loopback, link-local, multicast). If the first octet is not
// marked, the address is guaranteed to be a valid public IPv4 — allowing us to
// skip all individual checks in evaluateClientIP.
var ipv4SpecialFirstOctet [256]bool

func init() {
	// Every IPv4 prefix that evaluateClientIP may treat as non-public.
	// This must cover the same ranges as the checks in evaluateClientIP:
	// IsLoopback, IsLinkLocalUnicast, IsMulticast, IsUnspecified, IsPrivate,
	// plus all entries in reservedClientIPv4Prefixes.
	specialRanges := append([]netip.Prefix{
		mustParsePrefix("0.0.0.0/8"),      // IsUnspecified
		mustParsePrefix("10.0.0.0/8"),     // IsPrivate
		mustParsePrefix("127.0.0.0/8"),    // IsLoopback
		mustParsePrefix("169.254.0.0/16"), // IsLinkLocalUnicast
		mustParsePrefix("172.16.0.0/12"),  // IsPrivate
		mustParsePrefix("192.168.0.0/16"), // IsPrivate
		mustParsePrefix("224.0.0.0/3"),    // IsMulticast + future reserved (224.0.0.0–255.255.255.255)
	}, reservedClientIPv4Prefixes...)

	for _, prefix := range specialRanges {
		markIPv4SpecialOctets(prefix)
	}
}

// markIPv4SpecialOctets marks all first octets covered by prefix in the lookup table.
func markIPv4SpecialOctets(prefix netip.Prefix) {
	first := prefix.Addr().As4()[0]
	bits := prefix.Bits()
	if bits >= 8 {
		ipv4SpecialFirstOctet[first] = true
		return
	}

	// Prefix wider than /8 — covers multiple first octets.
	count := 1 << (8 - bits)
	for i := 0; i < count; i++ {
		ipv4SpecialFirstOctet[int(first)+i] = true
	}
}

func evaluateClientIP(ip netip.Addr, policy clientIPPolicy) clientIPDisposition {
	if !ip.IsValid() {
		return clientIPInvalid
	}

	// Fast path: IPv4 with first octet not in any special range is always
	// a valid public address. This avoids 6+ sequential method calls for the
	// common case.
	if ip.Is4() && !ipv4SpecialFirstOctet[ip.As4()[0]] {
		return clientIPValid
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return clientIPInvalid
	}

	if isReservedIP(ip) && !isAllowlistedReservedClientIP(ip, policy.AllowReservedClientPrefixes) {
		return clientIPReserved
	}

	if !policy.AllowPrivateIPs && ip.IsPrivate() {
		return clientIPPrivate
	}

	return clientIPValid
}

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

func isAllowlistedReservedClientIP(ip netip.Addr, allowlist []netip.Prefix) bool {
	if len(allowlist) == 0 || !ip.IsValid() {
		return false
	}

	ip = normalizeIP(ip)

	for _, prefix := range allowlist {
		if prefix.Contains(ip) {
			return true
		}
	}

	return false
}

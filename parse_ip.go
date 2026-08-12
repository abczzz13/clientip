package clientip

import (
	"net"
	"net/netip"
	"strings"
)

// normalizeIP puts an address in the canonical form used throughout the
// package: IPv6 zones removed and IPv4-in-IPv6 addresses unmapped.
//
// The zone is stripped first so a zoned IPv4-mapped address such as
// ::ffff:192.0.2.10%eth0 does not depend on Unmap discarding the zone.
func normalizeIP(ip netip.Addr) netip.Addr {
	if ip.Zone() != "" {
		ip = ip.WithZone("")
	}

	if ip.Is4In6() {
		return ip.Unmap()
	}

	return ip
}

// parseChainIP parses an IP from a chain value that has already been
// extracted and trimmed by a header parser. The returned address is
// normalized; see normalizeIP.
//
// This is intentionally stricter than parseIP: it accepts bare IPs,
// bracketed IPs, and bracketed IPs with a numeric port suffix only.
func parseChainIP(s string) netip.Addr {
	if ip, ok := parseNormalizedIP(s); ok {
		return ip
	}

	if len(s) < 2 || s[0] != '[' {
		return netip.Addr{}
	}

	end := strings.IndexByte(s, ']')
	if end <= 1 {
		return netip.Addr{}
	}

	rest := s[end+1:]
	if len(rest) > 0 {
		if rest[0] != ':' || len(rest) == 1 {
			return netip.Addr{}
		}
		for i := 1; i < len(rest); i++ {
			if rest[i] < '0' || rest[i] > '9' {
				return netip.Addr{}
			}
		}
	}

	if ip, ok := parseNormalizedIP(s[1:end]); ok {
		return ip
	}

	return netip.Addr{}
}

// parseIP extracts an IP address from the formats commonly found in proxy
// headers. The returned address is normalized; see normalizeIP.
func parseIP(s string) netip.Addr {
	s = strings.TrimSpace(s)
	if s == "" {
		return netip.Addr{}
	}

	s = trimMatchedChar(s, '"')
	s = trimMatchedChar(s, '\'')
	if s == "" {
		return netip.Addr{}
	}

	if looksLikeHostPort(s) {
		host, ok := splitHostPortHost(s)
		if !ok {
			return netip.Addr{}
		}

		ip, ok := parseNormalizedIP(host)
		if !ok {
			return netip.Addr{}
		}

		return ip
	}

	if ip, ok := parseNormalizedIP(s); ok {
		return ip
	}

	host, ok := splitHostPortHost(s)
	if !ok {
		return netip.Addr{}
	}

	ip, ok := parseNormalizedIP(host)
	if !ok {
		return netip.Addr{}
	}

	return ip
}

// parseRemoteAddr extracts an IP address from Request.RemoteAddr-like input.
// The returned address is normalized; see normalizeIP.
func parseRemoteAddr(s string) netip.Addr {
	host, ok := splitHostPortHost(s)
	if !ok {
		return parseIP(s)
	}

	ip, ok := parseNormalizedIP(host)
	if !ok {
		return netip.Addr{}
	}

	return ip
}

func looksLikeHostPort(s string) bool {
	if len(s) < 3 {
		return false
	}

	if s[0] == '[' {
		end := strings.LastIndexByte(s, ']')
		return end > 0 && end+1 < len(s) && s[end+1] == ':'
	}

	colon := strings.LastIndexByte(s, ':')
	if colon <= 0 || colon == len(s)-1 {
		return false
	}

	return strings.IndexByte(s[:colon], ':') == -1
}

func splitHostPortHost(s string) (string, bool) {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return "", false
	}

	return host, true
}

// parseNormalizedIP parses an IP literal that may carry one matched pair of
// brackets. Trimming is safe for bare literals too: no address netip accepts
// both starts with '[' and ends with ']'.
//
// This is the only place in the package that calls netip.ParseAddr, so every
// address the package hands back is normalized by construction.
func parseNormalizedIP(s string) (netip.Addr, bool) {
	s = trimMatchedPair(s, '[', ']')
	if s == "" {
		return netip.Addr{}, false
	}

	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}

	return normalizeIP(ip), true
}

func trimMatchedPair(s string, start, end byte) string {
	if len(s) < 2 {
		return s
	}

	if s[0] != start || s[len(s)-1] != end {
		return s
	}

	return s[1 : len(s)-1]
}

func trimMatchedChar(s string, ch byte) string {
	return trimMatchedPair(s, ch, ch)
}

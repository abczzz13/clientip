package clientip

import (
	"net"
	"net/netip"
	"strings"
)

// normalizeIP unmaps IPv4-in-IPv6 addresses to their IPv4 form.
func normalizeIP(ip netip.Addr) netip.Addr {
	if ip.Is4In6() {
		return ip.Unmap()
	}

	return ip
}

// parseChainIP parses an IP from a chain value that has already been
// extracted and trimmed by a header parser.
//
// This is intentionally stricter than parseIP: it accepts bare IPs,
// bracketed IPs, and bracketed IPs with a numeric port suffix only.
func parseChainIP(s string) netip.Addr {
	ip, err := netip.ParseAddr(s)
	if err == nil {
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

	ip, err = netip.ParseAddr(s[1:end])
	if err == nil {
		return ip
	}

	return netip.Addr{}
}

// parseIP extracts an IP address from the formats commonly found in proxy headers.
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

		ip, ok := parseHostIP(host)
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

	ip, ok := parseHostIP(host)
	if !ok {
		return netip.Addr{}
	}

	return ip
}

// parseRemoteAddr extracts an IP address from Request.RemoteAddr-like input.
func parseRemoteAddr(s string) netip.Addr {
	host, ok := splitHostPortHost(s)
	if !ok {
		return parseIP(s)
	}

	ip, ok := parseHostIP(host)
	if !ok {
		return netip.Addr{}
	}

	return ip
}

func parseHostIP(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		return ip, true
	}

	return parseNormalizedIP(host)
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

func parseNormalizedIP(s string) (netip.Addr, bool) {
	s = trimMatchedPair(s, '[', ']')
	if s == "" {
		return netip.Addr{}, false
	}

	ip, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Addr{}, false
	}

	return ip, true
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

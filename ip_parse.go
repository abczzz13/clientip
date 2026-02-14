package clientip

import (
	"net"
	"net/netip"
	"strings"
)

// parseIP extracts an IP address from various formats found in proxy headers.
// It handles:
//   - Leading/trailing whitespace: "  192.168.1.1  "
//   - Port suffixes: "192.168.1.1:8080" or "[::1]:8080"
//   - Quoted values: "\"192.168.1.1\"" or "'192.168.1.1'"
//   - IPv6 brackets: "[::1]"
//
// The function normalizes these common variations before calling
// netip.ParseAddr for the actual parsing. This approach is lenient with
// formatting (trimming, removing ports/quotes) but still relies on Go's
// standard IP validation. Validation of whether the IP is plausible (not
// loopback, private, etc.) is handled separately by isPlausibleClientIP.
//
// Returns an invalid netip.Addr (IsValid() == false) if parsing fails.
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

func parseHostIP(host string) (netip.Addr, bool) {
	ip, err := netip.ParseAddr(host)
	if err == nil {
		return ip, true
	}

	return parseNormalizedIP(host)
}

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

func normalizeIP(ip netip.Addr) netip.Addr {
	if ip.Is4In6() {
		return ip.Unmap()
	}
	return ip
}

// trimMatchedPair removes one leading and trailing delimiter when both match.
func trimMatchedPair(s string, start, end byte) string {
	if len(s) < 2 {
		return s
	}

	if s[0] != start || s[len(s)-1] != end {
		return s
	}

	return s[1 : len(s)-1]
}

// trimMatchedChar removes one matching leading and trailing character.
func trimMatchedChar(s string, ch byte) string {
	return trimMatchedPair(s, ch, ch)
}

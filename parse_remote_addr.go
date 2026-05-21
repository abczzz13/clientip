package clientip

import "net/netip"

// ParseRemoteAddr parses and normalizes Request.RemoteAddr-style input without
// applying extractor plausibility policy.
//
// It accepts host:port values, bracketed IPv6 host:port values, and bare IP
// literals. IPv4-mapped IPv6 addresses are normalized to IPv4. Empty input
// returns ErrSourceUnavailable; unparsable input returns ErrInvalidIP wrapped in
// RemoteAddrError.
func ParseRemoteAddr(remoteAddr string) (netip.Addr, error) {
	if remoteAddr == "" {
		return netip.Addr{}, &ExtractionError{Err: ErrSourceUnavailable, Source: SourceRemoteAddr}
	}

	ip := parseRemoteAddr(remoteAddr)
	if !ip.IsValid() {
		return netip.Addr{}, &RemoteAddrError{
			ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
			RemoteAddr:      remoteAddr,
		}
	}

	return normalizeIP(ip), nil
}

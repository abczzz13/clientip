package clientip

import "net/netip"

// ParseRemoteAddr parses and normalizes Request.RemoteAddr-style input without
// applying extractor plausibility policy.
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

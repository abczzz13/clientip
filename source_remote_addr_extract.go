package clientip

type remoteAddrExtractor struct {
	clientIPPolicy clientIPPolicy
}

// extract resolves the immediate connecting peer. This is the only source that
// does not depend on trusted proxy configuration.
func (e remoteAddrExtractor) extract(remoteAddr string, source Source) (Extraction, *extractionFailure) {
	if remoteAddr == "" {
		return Extraction{}, errSourceUnavailable
	}

	ip := parseRemoteAddr(remoteAddr)
	disposition := evaluateClientIP(ip, e.clientIPPolicy)
	if disposition != clientIPValid {
		return Extraction{}, &extractionFailure{
			kind:                failureInvalidClientIP,
			source:              source,
			remoteAddr:          remoteAddr,
			clientIPDisposition: disposition,
		}
	}

	return Extraction{
		IP:     normalizeIP(ip),
		Source: source,
	}, nil
}

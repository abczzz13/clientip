package clientip

type remoteAddrExtractor struct {
	clientIPPolicy clientIPPolicy
}

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

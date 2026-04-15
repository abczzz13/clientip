package clientip

type singleHeaderPolicy struct {
	headerName   string
	clientIP     clientIPPolicy
	trustedProxy proxyPolicy
}

type singleHeaderExtractor struct {
	policy singleHeaderPolicy
}

func (e singleHeaderExtractor) extract(req requestView, source Source) (Extraction, *extractionFailure) {
	headerValues := req.valuesCanonical(e.policy.headerName)
	if len(headerValues) == 0 {
		return Extraction{}, errSourceUnavailable
	}

	if len(headerValues) > 1 {
		return Extraction{}, &extractionFailure{
			kind:        failureMultipleHeaders,
			source:      source,
			headerName:  e.policy.headerName,
			headerCount: len(headerValues),
			remoteAddr:  req.remoteAddr(),
		}
	}

	headerValue := headerValues[0]
	if headerValue == "" {
		return Extraction{}, errSourceUnavailable
	}

	if len(e.policy.trustedProxy.TrustedProxyCIDRs) > 0 {
		remoteIP := parseRemoteAddr(req.remoteAddr())
		if !isTrustedProxy(remoteIP, e.policy.trustedProxy.TrustedProxyMatch, e.policy.trustedProxy.TrustedProxyCIDRs) {
			return Extraction{}, &extractionFailure{
				kind:              failureUntrustedProxy,
				source:            source,
				headerName:        e.policy.headerName,
				chain:             headerValue,
				trustedProxyCount: 0,
				minTrustedProxies: e.policy.trustedProxy.MinTrustedProxies,
				maxTrustedProxies: e.policy.trustedProxy.MaxTrustedProxies,
			}
		}
	}

	ip := parseIP(headerValue)
	disposition := evaluateClientIP(ip, e.policy.clientIP)
	if disposition != clientIPValid {
		return Extraction{}, &extractionFailure{
			kind:                failureInvalidClientIP,
			source:              source,
			extractedIP:         headerValue,
			clientIPDisposition: disposition,
		}
	}

	return Extraction{
		IP:     normalizeIP(ip),
		Source: source,
	}, nil
}

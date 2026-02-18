package clientip

import (
	"context"
	"net/http"
)

type singleHeaderSource struct {
	extractor      *Extractor
	headerName     string
	headerKey      string
	sourceName     string
	unavailableErr error
}

func (s *singleHeaderSource) Name() string {
	return s.sourceName
}

func (s *singleHeaderSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Name()
	headerValues := r.Header[s.headerKey]
	if len(headerValues) == 0 {
		return extractionResult{}, sourceUnavailableError(s.unavailableErr, sourceName)
	}

	if len(headerValues) > 1 {
		s.extractor.config.metrics.RecordSecurityEvent(securityEventMultipleHeaders)
		s.extractor.logSecurityWarning(ctx, r, sourceName, securityEventMultipleHeaders, "multiple single-IP headers received - possible spoofing attempt",
			"header", s.headerName,
			"header_count", len(headerValues),
		)
		s.extractor.config.metrics.RecordExtractionFailure(sourceName)
		return extractionResult{}, &MultipleHeadersError{
			ExtractionError: ExtractionError{
				Err:    ErrMultipleSingleIPHeaders,
				Source: sourceName,
			},
			HeaderCount: len(headerValues),
			HeaderName:  s.headerName,
			RemoteAddr:  r.RemoteAddr,
		}
	}

	headerValue := headerValues[0]
	if headerValue == "" {
		return extractionResult{}, sourceUnavailableError(s.unavailableErr, sourceName)
	}

	if len(s.extractor.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseRemoteAddr(r.RemoteAddr)
		if !s.extractor.isTrustedProxy(remoteIP) {
			s.extractor.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			s.extractor.logSecurityWarning(ctx, r, sourceName, securityEventUntrustedProxy, "request received from untrusted proxy while single-header source is present",
				"header", s.headerName,
			)
			s.extractor.config.metrics.RecordExtractionFailure(sourceName)
			return extractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: sourceName,
				},
				Chain:             headerValue,
				TrustedProxyCount: 0,
				MinTrustedProxies: s.extractor.config.minTrustedProxies,
				MaxTrustedProxies: s.extractor.config.maxTrustedProxies,
			}
		}
	}

	ip := parseIP(headerValue)
	if !s.extractor.isPlausibleClientIP(ip) {
		s.extractor.config.metrics.RecordExtractionFailure(sourceName)
		return extractionResult{}, &InvalidIPError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: sourceName,
			},
			ExtractedIP: headerValue,
		}
	}

	s.extractor.config.metrics.RecordExtractionSuccess(sourceName)
	return extractionResult{IP: normalizeIP(ip), Source: sourceName}, nil
}

type remoteAddrSource struct {
	extractor      *Extractor
	unavailableErr error
}

func (s *remoteAddrSource) Name() string {
	return SourceRemoteAddr
}

func (s *remoteAddrSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Name()
	remoteAddr := r.RemoteAddr
	result, err := s.extractor.extractRemoteAddr(remoteAddr)
	if err != nil {
		return extractionResult{}, wrapSourceUnavailableError(err, s.unavailableErr, sourceName)
	}

	return result, nil
}

func (e *Extractor) extractRemoteAddr(remoteAddr string) (extractionResult, error) {
	if remoteAddr == "" {
		return extractionResult{}, &ExtractionError{Err: ErrSourceUnavailable, Source: SourceRemoteAddr}
	}

	ip := parseRemoteAddr(remoteAddr)
	if !e.isPlausibleClientIP(ip) {
		e.config.metrics.RecordExtractionFailure(SourceRemoteAddr)
		return extractionResult{}, &RemoteAddrError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: SourceRemoteAddr,
			},
			RemoteAddr: remoteAddr,
		}
	}

	e.config.metrics.RecordExtractionSuccess(SourceRemoteAddr)
	return extractionResult{IP: normalizeIP(ip), Source: SourceRemoteAddr}, nil
}

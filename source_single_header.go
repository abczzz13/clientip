package clientip

import (
	"context"
	"net/http"
)

type singleHeaderSource struct {
	extractor      *Extractor
	headerName     string
	headerKey      string
	sourceName     Source
	unavailableErr error
}

func (s *singleHeaderSource) Name() string {
	return s.sourceName.String()
}

func (s *singleHeaderSource) Source() Source {
	return s.sourceName
}

func (s *singleHeaderSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Source()
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
		s.extractor.config.metrics.RecordExtractionFailure(sourceName.String())
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
			s.extractor.config.metrics.RecordExtractionFailure(sourceName.String())
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
		s.extractor.config.metrics.RecordExtractionFailure(sourceName.String())
		return extractionResult{}, &InvalidIPError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: sourceName,
			},
			ExtractedIP: headerValue,
		}
	}

	s.extractor.config.metrics.RecordExtractionSuccess(sourceName.String())
	return extractionResult{IP: normalizeIP(ip), Source: sourceName}, nil
}

type remoteAddrSource struct {
	extractor      *Extractor
	sourceName     Source
	unavailableErr error
}

func (s *remoteAddrSource) Name() string {
	if !s.sourceName.valid() {
		return builtinSource(sourceRemoteAddr).String()
	}

	return s.sourceName.String()
}

func (s *remoteAddrSource) Source() Source {
	if !s.sourceName.valid() {
		return builtinSource(sourceRemoteAddr)
	}

	return s.sourceName
}

func (s *remoteAddrSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Source()
	remoteAddr := r.RemoteAddr
	result, err := s.extractor.extractRemoteAddr(remoteAddr)
	if err != nil {
		return extractionResult{}, wrapSourceUnavailableError(err, s.unavailableErr, sourceName)
	}

	return result, nil
}

func (e *Extractor) extractRemoteAddr(remoteAddr string) (extractionResult, error) {
	remoteSource := builtinSource(sourceRemoteAddr)

	if remoteAddr == "" {
		return extractionResult{}, &ExtractionError{Err: ErrSourceUnavailable, Source: remoteSource}
	}

	ip := parseRemoteAddr(remoteAddr)
	if !e.isPlausibleClientIP(ip) {
		e.config.metrics.RecordExtractionFailure(remoteSource.String())
		return extractionResult{}, &RemoteAddrError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: remoteSource,
			},
			RemoteAddr: remoteAddr,
		}
	}

	e.config.metrics.RecordExtractionSuccess(remoteSource.String())
	return extractionResult{IP: normalizeIP(ip), Source: remoteSource}, nil
}

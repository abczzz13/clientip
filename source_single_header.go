package clientip

import (
	"context"
	"net/http"
)

type singleHeaderSource struct {
	extractor      *Extractor
	headerName     string
	sourceName     string
	unavailableErr error
}

func (s *singleHeaderSource) Name() string {
	return s.sourceName
}

func (s *singleHeaderSource) sourceUnavailableError() error {
	if s.unavailableErr != nil {
		return s.unavailableErr
	}

	return &ExtractionError{Err: ErrSourceUnavailable, Source: s.Name()}
}

func (s *singleHeaderSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	headerValues := r.Header.Values(s.headerName)
	if len(headerValues) == 0 {
		return extractionResult{}, s.sourceUnavailableError()
	}

	if len(headerValues) > 1 {
		s.extractor.config.metrics.RecordSecurityEvent(securityEventMultipleHeaders)
		s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventMultipleHeaders, "multiple single-IP headers received - possible spoofing attempt",
			"header", s.headerName,
			"header_count", len(headerValues),
		)
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, &MultipleHeadersError{
			ExtractionError: ExtractionError{
				Err:    ErrMultipleSingleIPHeaders,
				Source: s.Name(),
			},
			HeaderCount: len(headerValues),
			HeaderName:  s.headerName,
			RemoteAddr:  r.RemoteAddr,
		}
	}

	headerValue := headerValues[0]
	if headerValue == "" {
		return extractionResult{}, s.sourceUnavailableError()
	}

	if len(s.extractor.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseRemoteAddr(r.RemoteAddr)
		if !s.extractor.isTrustedProxy(remoteIP) {
			s.extractor.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventUntrustedProxy, "request received from untrusted proxy while single-header source is present",
				"header", s.headerName,
			)
			s.extractor.config.metrics.RecordExtractionFailure(s.Name())
			return extractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: s.Name(),
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
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, &InvalidIPError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: s.Name(),
			},
			ExtractedIP: headerValue,
		}
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	return extractionResult{IP: normalizeIP(ip), Source: s.Name()}, nil
}

type remoteAddrSource struct {
	extractor      *Extractor
	unavailableErr error
}

func (s *remoteAddrSource) Name() string {
	return SourceRemoteAddr
}

func (s *remoteAddrSource) sourceUnavailableError() error {
	if s.unavailableErr != nil {
		return s.unavailableErr
	}

	return &ExtractionError{Err: ErrSourceUnavailable, Source: s.Name()}
}

func (s *remoteAddrSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	if r.RemoteAddr == "" {
		return extractionResult{}, s.sourceUnavailableError()
	}

	ip := parseRemoteAddr(r.RemoteAddr)
	if !s.extractor.isPlausibleClientIP(ip) {
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, &RemoteAddrError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: s.Name(),
			},
			RemoteAddr: r.RemoteAddr,
		}
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	return extractionResult{IP: normalizeIP(ip), Source: s.Name()}, nil
}

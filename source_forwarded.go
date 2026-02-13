package clientip

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type forwardedForSource struct {
	extractor *Extractor
}

type forwardedSource struct {
	extractor *Extractor
}

func (s *forwardedForSource) Name() string {
	return SourceXForwardedFor
}

func (s *forwardedSource) Name() string {
	return SourceForwarded
}

func (s *forwardedSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	forwardedValues := r.Header.Values("Forwarded")

	if len(forwardedValues) == 0 {
		return extractionResult{}, &ExtractionError{
			Err:    ErrSourceUnavailable,
			Source: s.Name(),
		}
	}

	return s.extractor.extractChainSource(
		ctx,
		r,
		s.Name(),
		forwardedValues,
		strings.Join(forwardedValues, ", "),
		"request received from untrusted proxy while Forwarded is present",
		"Forwarded chain exceeds configured maximum length",
		s.extractor.parseForwardedValues,
		func(err error) {
			if !errors.Is(err, ErrInvalidForwardedHeader) {
				return
			}

			s.extractor.config.metrics.RecordSecurityEvent(securityEventMalformedForwarded)
			s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventMalformedForwarded, "malformed Forwarded header received", "parse_error", err.Error())
		},
	)
}

func (s *forwardedForSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	xffValues := r.Header.Values("X-Forwarded-For")

	if len(xffValues) == 0 {
		return extractionResult{}, &ExtractionError{
			Err:    ErrSourceUnavailable,
			Source: s.Name(),
		}
	}

	if len(xffValues) > 1 {
		s.extractor.config.metrics.RecordSecurityEvent(securityEventMultipleHeaders)
		s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventMultipleHeaders, "multiple X-Forwarded-For headers received - possible spoofing attempt",
			"header_count", len(xffValues),
		)
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, &MultipleHeadersError{
			ExtractionError: ExtractionError{
				Err:    ErrMultipleXFFHeaders,
				Source: s.Name(),
			},
			HeaderCount: len(xffValues),
			HeaderName:  "X-Forwarded-For",
			RemoteAddr:  r.RemoteAddr,
		}
	}

	return s.extractor.extractChainSource(
		ctx,
		r,
		s.Name(),
		xffValues,
		xffValues[0],
		"request received from untrusted proxy while X-Forwarded-For is present",
		"X-Forwarded-For chain exceeds configured maximum length",
		s.extractor.parseXFFValues,
		nil,
	)
}

package clientip

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type forwardedForSource struct {
	extractor      *Extractor
	unavailableErr error
}

type forwardedSource struct {
	extractor      *Extractor
	unavailableErr error
}

func (s *forwardedForSource) Name() string {
	return SourceXForwardedFor
}

func (s *forwardedSource) Name() string {
	return SourceForwarded
}

func (s *forwardedSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Name()
	forwardedValues := r.Header["Forwarded"]
	if len(forwardedValues) == 0 {
		return extractionResult{}, sourceUnavailableError(s.unavailableErr, sourceName)
	}

	return s.extractor.extractChainSource(
		ctx,
		r,
		sourceName,
		forwardedValues,
		func() string {
			return strings.Join(forwardedValues, ", ")
		},
		"request received from untrusted proxy while Forwarded is present",
		"Forwarded chain exceeds configured maximum length",
		s.extractor.parseForwardedValues,
		func(err error) {
			if !errors.Is(err, ErrInvalidForwardedHeader) {
				return
			}

			s.extractor.config.metrics.RecordSecurityEvent(securityEventMalformedForwarded)
			s.extractor.logSecurityWarning(ctx, r, sourceName, securityEventMalformedForwarded, "malformed Forwarded header received", "parse_error", err.Error())
		},
	)
}

func (s *forwardedForSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Name()
	xffValues := r.Header["X-Forwarded-For"]
	if len(xffValues) == 0 {
		return extractionResult{}, sourceUnavailableError(s.unavailableErr, sourceName)
	}

	return s.extractor.extractChainSource(
		ctx,
		r,
		sourceName,
		xffValues,
		func() string {
			return strings.Join(xffValues, ", ")
		},
		"request received from untrusted proxy while X-Forwarded-For is present",
		"X-Forwarded-For chain exceeds configured maximum length",
		s.extractor.parseXFFValues,
		nil,
	)
}

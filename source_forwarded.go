package clientip

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

type forwardedForSource struct {
	extractor      *Extractor
	sourceName     Source
	unavailableErr error
}

type forwardedSource struct {
	extractor      *Extractor
	sourceName     Source
	unavailableErr error
}

func (s *forwardedForSource) Name() string {
	if !s.sourceName.valid() {
		return builtinSource(sourceXForwardedFor).String()
	}

	return s.sourceName.String()
}

func (s *forwardedSource) Name() string {
	if !s.sourceName.valid() {
		return builtinSource(sourceForwarded).String()
	}

	return s.sourceName.String()
}

func (s *forwardedForSource) Source() Source {
	if !s.sourceName.valid() {
		return builtinSource(sourceXForwardedFor)
	}

	return s.sourceName
}

func (s *forwardedSource) Source() Source {
	if !s.sourceName.valid() {
		return builtinSource(sourceForwarded)
	}

	return s.sourceName
}

func (s *forwardedSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	sourceName := s.Source()
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
	sourceName := s.Source()
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

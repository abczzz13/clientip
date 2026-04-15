package clientip

import (
	"context"
	"errors"
)

// ResultKind is a coarse-grained classification for extraction and resolution
// results.
//
// ClassifyError returns ResultSuccess for nil and ResultUnknown for non-nil
// errors outside the package's standard extraction and resolution surface.
type ResultKind uint8

const (
	// ResultUnknown indicates a non-nil error outside the package's standard
	// extraction and resolution categories.
	ResultUnknown ResultKind = iota
	// ResultSuccess indicates the operation completed without error.
	ResultSuccess
	// ResultUnavailable indicates the selected source was not present.
	ResultUnavailable
	// ResultInvalid indicates invalid request input or an invalid client IP.
	ResultInvalid
	// ResultUntrusted indicates the request failed trusted-proxy validation.
	ResultUntrusted
	// ResultMalformed indicates malformed or conflicting proxy-header input.
	ResultMalformed
	// ResultCanceled indicates context cancellation or deadline expiry.
	ResultCanceled
)

// ClassifyError maps the package's detailed error surface into a smaller set of
// policy-oriented result kinds.
//
// This helper is additive: typed errors and errors.Is / errors.As remain the
// detailed interface when callers need source-specific diagnostics.
func ClassifyError(err error) ResultKind {
	switch {
	case err == nil:
		return ResultSuccess
	case errors.Is(err, context.Canceled), errors.Is(err, context.DeadlineExceeded):
		return ResultCanceled
	case errors.Is(err, ErrSourceUnavailable):
		return ResultUnavailable
	case errors.Is(err, ErrUntrustedProxy),
		errors.Is(err, ErrNoTrustedProxies),
		errors.Is(err, ErrTooFewTrustedProxies),
		errors.Is(err, ErrTooManyTrustedProxies):
		return ResultUntrusted
	case errors.Is(err, ErrInvalidForwardedHeader),
		errors.Is(err, ErrChainTooLong),
		errors.Is(err, ErrMultipleSingleIPHeaders):
		return ResultMalformed
	case errors.Is(err, ErrInvalidIP), errors.Is(err, ErrNilRequest):
		return ResultInvalid
	default:
		return ResultUnknown
	}
}

package clientip

import (
	"errors"
	"fmt"
)

// extractChainSource adapts chain extractor output into orchestration-level
// errors. Source-specific parser adapters have already wrapped syntax and
// length errors; policy failures become public typed errors through
// adaptChainFailure.
func (e *extractor) extractChainSource(
	r requestView,
	source *configuredSource,
	chainTooLongMessage string,
	untrustedProxyMessage string,
	handleParseError func(error),
) (Extraction, error) {
	result, failure, err := source.chain.extract(r, source.source)
	if err != nil {
		e.handleChainError(r, source.source, err, chainTooLongMessage, handleParseError)
		return Extraction{}, err
	}
	if failure != nil {
		if failure.kind == failureSourceUnavailable {
			return Extraction{}, source.unavailableErr
		}
		return Extraction{}, e.adaptChainFailure(r, source.source, failure, untrustedProxyMessage)
	}

	return result, nil
}

func (e *extractor) extractSingleHeaderSource(r requestView, source *configuredSource) (Extraction, error) {
	result, failure := source.single.extract(r, source.source)
	if failure != nil {
		if failure.kind == failureSourceUnavailable {
			return Extraction{}, source.unavailableErr
		}
		return Extraction{}, e.adaptSingleHeaderFailure(r, source.source, failure)
	}

	return result, nil
}

func (e *extractor) extractRemoteAddrSource(r requestView, source *configuredSource) (Extraction, error) {
	result, failure := source.remote.extract(r.remoteAddr(), source.source)
	if failure != nil {
		if failure.kind == failureSourceUnavailable {
			return Extraction{}, source.unavailableErr
		}
		return Extraction{}, adaptRemoteAddrFailure(failure, source.source)
	}

	return result, nil
}

// logSecurityWarning emits stable base attributes with the request context so
// caller-provided loggers can attach trace/span metadata.
func (e *extractor) logSecurityWarning(r requestView, source Source, event, msg string, attrs ...any) {
	if e.config.loggerNoop {
		return
	}

	baseAttrs := []any{
		"event", event,
		"source", source.String(),
		"path", r.path(),
		"remote_addr", r.remoteAddr(),
	}

	baseAttrs = append(baseAttrs, attrs...)
	e.config.logger.WarnContext(r.context(), msg, baseAttrs...)
}

func proxyValidationWarningDetails(err error) (event, msg string, ok bool) {
	switch {
	case errors.Is(err, ErrNoTrustedProxies):
		return SecurityEventNoTrustedProxies, "no trusted proxies found in request chain", true
	case errors.Is(err, ErrTooFewTrustedProxies):
		return SecurityEventTooFewTrustedProxies, "trusted proxy count below configured minimum", true
	case errors.Is(err, ErrTooManyTrustedProxies):
		return SecurityEventTooManyTrustedProxies, "trusted proxy count exceeds configured maximum", true
	default:
		return "", "", false
	}
}

func (e *extractor) logProxyValidationWarning(r requestView, source Source, err error) {
	if e.config.loggerNoop {
		return
	}

	event, msg, ok := proxyValidationWarningDetails(err)
	if !ok {
		return
	}

	var proxyErr *ProxyValidationError
	if errors.As(err, &proxyErr) {
		e.logSecurityWarning(
			r, source, event, msg,
			"trusted_proxy_count", proxyErr.TrustedProxyCount,
			"min_trusted_proxies", proxyErr.MinTrustedProxies,
			"max_trusted_proxies", proxyErr.MaxTrustedProxies,
		)
		return
	}

	e.logSecurityWarning(r, source, event, msg)
}

func (e *extractor) handleChainError(
	r requestView,
	source Source,
	err error,
	chainTooLongMessage string,
	handleParseError func(error),
) {
	if errors.Is(err, ErrChainTooLong) && !e.config.loggerNoop {
		var chainErr *ChainTooLongError
		if errors.As(err, &chainErr) {
			e.logSecurityWarning(
				r, source, SecurityEventChainTooLong, chainTooLongMessage,
				"chain_length", chainErr.ChainLength,
				"max_length", chainErr.MaxLength,
			)
		} else {
			e.logSecurityWarning(r, source, SecurityEventChainTooLong, chainTooLongMessage)
		}
	}

	if handleParseError != nil {
		handleParseError(err)
	}
}

// adaptChainFailure converts chain-source policy failures into public errors.
// Keep new chain failure kinds here so logging and typed errors stay centralized.
func (e *extractor) adaptChainFailure(r requestView, source Source, failure *extractionFailure, untrustedProxyMessage string) error {
	if failure == nil {
		return &ExtractionError{Err: ErrInvalidIP, Source: source}
	}

	switch failure.kind {
	case failureSourceUnavailable:
		return &ExtractionError{Err: ErrSourceUnavailable, Source: source}
	case failureUntrustedProxy:
		e.logSecurityWarning(r, source, SecurityEventUntrustedProxy, untrustedProxyMessage)
		return &ProxyValidationError{
			ExtractionError:   ExtractionError{Err: ErrUntrustedProxy, Source: source},
			Chain:             failure.chain,
			TrustedProxyCount: failure.trustedProxyCount,
			MinTrustedProxies: failure.minTrustedProxies,
			MaxTrustedProxies: failure.maxTrustedProxies,
		}
	case failureProxyValidation:
		err := &ProxyValidationError{
			ExtractionError: ExtractionError{
				Err:    proxyCountError(failure.trustedProxyCount, e.config.proxy),
				Source: source,
			},
			Chain:             failure.chain,
			TrustedProxyCount: failure.trustedProxyCount,
			MinTrustedProxies: failure.minTrustedProxies,
			MaxTrustedProxies: failure.maxTrustedProxies,
		}
		e.logProxyValidationWarning(r, source, err)
		return err
	case failureEmptyChain:
		return &ExtractionError{Err: ErrInvalidIP, Source: source}
	case failureInvalidClientIP:
		return &InvalidIPError{
			ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: source},
			Chain:           failure.chain,
			ExtractedIP:     failure.extractedIP,
			Index:           failure.index,
			TrustedProxies:  failure.trustedProxyCount,
		}
	default:
		return &ExtractionError{Err: ErrInvalidIP, Source: source}
	}
}

// adaptSingleHeaderFailure converts single-header policy failures into public
// errors and emits the spoofing-related warnings for duplicate/untrusted input.
func (e *extractor) adaptSingleHeaderFailure(r requestView, sourceName Source, failure *extractionFailure) error {
	if failure == nil {
		return &ExtractionError{Err: ErrInvalidIP, Source: sourceName}
	}

	switch failure.kind {
	case failureSourceUnavailable:
		return &ExtractionError{Err: ErrSourceUnavailable, Source: sourceName}
	case failureMultipleHeaders:
		e.logSecurityWarning(
			r, sourceName, SecurityEventMultipleHeaders, "multiple single-IP headers received - possible spoofing attempt",
			"header", failure.headerName,
			"header_count", failure.headerCount,
		)
		return &MultipleHeadersError{
			ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: sourceName},
			HeaderCount:     failure.headerCount,
			HeaderName:      failure.headerName,
			RemoteAddr:      failure.remoteAddr,
		}
	case failureUntrustedProxy:
		e.logSecurityWarning(
			r, sourceName, SecurityEventUntrustedProxy, "request received from untrusted proxy while single-header source is present",
			"header", failure.headerName,
		)
		return &ProxyValidationError{
			ExtractionError:   ExtractionError{Err: ErrUntrustedProxy, Source: sourceName},
			Chain:             failure.chain,
			TrustedProxyCount: failure.trustedProxyCount,
			MinTrustedProxies: failure.minTrustedProxies,
			MaxTrustedProxies: failure.maxTrustedProxies,
		}
	case failureInvalidClientIP:
		return &InvalidIPError{
			ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: sourceName},
			ExtractedIP:     failure.extractedIP,
		}
	default:
		return &ExtractionError{Err: ErrInvalidIP, Source: sourceName}
	}
}

// adaptRemoteAddrFailure converts RemoteAddr parsing/policy failures into the
// public RemoteAddrError shape.
func adaptRemoteAddrFailure(failure *extractionFailure, sourceName Source) error {
	if failure == nil {
		return &ExtractionError{Err: ErrInvalidIP, Source: sourceName}
	}

	switch failure.kind {
	case failureSourceUnavailable:
		return &ExtractionError{Err: ErrSourceUnavailable, Source: sourceName}
	case failureInvalidClientIP:
		return &RemoteAddrError{
			ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: sourceName},
			RemoteAddr:      failure.remoteAddr,
		}
	default:
		return &ExtractionError{Err: ErrInvalidIP, Source: sourceName}
	}
}

// adaptForwardedParseError marks malformed RFC 7239 input with the Forwarded
// sentinel while preserving chain-length errors as their own category.
func adaptForwardedParseError(err error, source Source, extractor *extractor) error {
	if chainErr := adaptChainLengthError(err, source, extractor); chainErr != nil {
		return chainErr
	}

	return &ExtractionError{
		Err:    fmt.Errorf("%w: %w", ErrInvalidForwardedHeader, err),
		Source: source,
	}
}

// adaptXFFParseError currently only maps XFF parser errors that are chain-limit
// failures; other XFF parsing is intentionally permissive.
func adaptXFFParseError(err error, source Source, extractor *extractor) error {
	if chainErr := adaptChainLengthError(err, source, extractor); chainErr != nil {
		return chainErr
	}

	return err
}

func adaptChainLengthError(err error, source Source, _ *extractor) error {
	var chainErr *chainTooLongParseError
	if !errors.As(err, &chainErr) {
		return nil
	}

	return &ChainTooLongError{
		ExtractionError: ExtractionError{Err: ErrChainTooLong, Source: source},
		ChainLength:     chainErr.ChainLength,
		MaxLength:       chainErr.MaxLength,
	}
}

// proxyCountError re-runs count validation to map policy failures onto stable
// public sentinel errors used by errors.Is and Result.Classify.
func proxyCountError(trustedCount int, proxy proxyPolicy) error {
	err := validateProxyCountPolicy(trustedCount, proxy)
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, ErrNoTrustedProxies):
		return ErrNoTrustedProxies
	case errors.Is(err, ErrTooFewTrustedProxies):
		return ErrTooFewTrustedProxies
	case errors.Is(err, ErrTooManyTrustedProxies):
		return ErrTooManyTrustedProxies
	default:
		return err
	}
}

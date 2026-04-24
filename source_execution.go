package clientip

import (
	"context"
	"errors"
	"fmt"
)

func (e *Extractor) extractChainSource(
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

	e.config.metrics.RecordExtractionSuccess(source.name)
	return result, nil
}

func (e *Extractor) extractSingleHeaderSource(r requestView, source *configuredSource) (Extraction, error) {
	result, failure := source.single.extract(r, source.source)
	if failure != nil {
		if failure.kind == failureSourceUnavailable {
			return Extraction{}, source.unavailableErr
		}
		return Extraction{}, e.adaptSingleHeaderFailure(r, source.source, failure)
	}

	e.config.metrics.RecordExtractionSuccess(source.name)
	return result, nil
}

func (e *Extractor) extractRemoteAddrSource(r requestView, source *configuredSource) (Extraction, error) {
	result, failure := source.remote.extract(r.remoteAddr(), source.source)
	if failure != nil {
		if failure.kind == failureSourceUnavailable {
			return Extraction{}, source.unavailableErr
		}
		e.recordInvalidClientIPDisposition(failure.clientIPDisposition)
		e.config.metrics.RecordExtractionFailure(source.name)
		return Extraction{}, adaptRemoteAddrFailure(failure, source.source)
	}

	e.config.metrics.RecordExtractionSuccess(source.name)
	return result, nil
}

func sourceIsTerminalError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	if errors.Is(err, ErrSourceUnavailable) {
		return false
	}

	return errors.Is(err, ErrInvalidIP) ||
		errors.Is(err, ErrMultipleSingleIPHeaders) ||
		errors.Is(err, ErrUntrustedProxy) ||
		errors.Is(err, ErrNoTrustedProxies) ||
		errors.Is(err, ErrTooFewTrustedProxies) ||
		errors.Is(err, ErrTooManyTrustedProxies) ||
		errors.Is(err, ErrChainTooLong) ||
		errors.Is(err, ErrInvalidForwardedHeader)
}

func (e *Extractor) logSecurityWarning(r requestView, source Source, event, msg string, attrs ...any) {
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

func (e *Extractor) logProxyValidationWarning(r requestView, source Source, err error) {
	event, msg, ok := proxyValidationWarningDetails(err)
	if !ok {
		return
	}

	var proxyErr *ProxyValidationError
	if errors.As(err, &proxyErr) {
		e.logSecurityWarning(r, source, event, msg,
			"trusted_proxy_count", proxyErr.TrustedProxyCount,
			"min_trusted_proxies", proxyErr.MinTrustedProxies,
			"max_trusted_proxies", proxyErr.MaxTrustedProxies,
		)
		return
	}

	e.logSecurityWarning(r, source, event, msg)
}

func (e *Extractor) handleChainError(
	r requestView,
	source Source,
	err error,
	chainTooLongMessage string,
	handleParseError func(error),
) {
	if errors.Is(err, ErrChainTooLong) {
		var chainErr *ChainTooLongError
		if errors.As(err, &chainErr) {
			e.logSecurityWarning(r, source, SecurityEventChainTooLong, chainTooLongMessage,
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

	e.config.metrics.RecordExtractionFailure(source.String())
}

func (e *Extractor) adaptChainFailure(r requestView, source Source, failure *extractionFailure, untrustedProxyMessage string) error {
	if failure == nil {
		return &ExtractionError{Err: ErrInvalidIP, Source: source}
	}

	switch failure.kind {
	case failureSourceUnavailable:
		return &ExtractionError{Err: ErrSourceUnavailable, Source: source}
	case failureUntrustedProxy:
		e.config.metrics.RecordSecurityEvent(SecurityEventUntrustedProxy)
		e.logSecurityWarning(r, source, SecurityEventUntrustedProxy, untrustedProxyMessage)
		e.config.metrics.RecordExtractionFailure(source.String())
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
				Err:    e.validateProxyCount(failure.trustedProxyCount),
				Source: source,
			},
			Chain:             failure.chain,
			TrustedProxyCount: failure.trustedProxyCount,
			MinTrustedProxies: failure.minTrustedProxies,
			MaxTrustedProxies: failure.maxTrustedProxies,
		}
		e.logProxyValidationWarning(r, source, err)
		e.config.metrics.RecordExtractionFailure(source.String())
		return err
	case failureEmptyChain:
		e.config.metrics.RecordExtractionFailure(source.String())
		return &ExtractionError{Err: ErrInvalidIP, Source: source}
	case failureInvalidClientIP:
		e.recordInvalidClientIPDisposition(failure.clientIPDisposition)
		e.config.metrics.RecordExtractionFailure(source.String())
		return &InvalidIPError{
			ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: source},
			Chain:           failure.chain,
			ExtractedIP:     failure.extractedIP,
			Index:           failure.index,
			TrustedProxies:  failure.trustedProxyCount,
		}
	default:
		e.config.metrics.RecordExtractionFailure(source.String())
		return &ExtractionError{Err: ErrInvalidIP, Source: source}
	}
}

func (e *Extractor) adaptSingleHeaderFailure(r requestView, sourceName Source, failure *extractionFailure) error {
	if failure == nil {
		return &ExtractionError{Err: ErrInvalidIP, Source: sourceName}
	}

	switch failure.kind {
	case failureSourceUnavailable:
		return &ExtractionError{Err: ErrSourceUnavailable, Source: sourceName}
	case failureMultipleHeaders:
		e.config.metrics.RecordSecurityEvent(SecurityEventMultipleHeaders)
		e.logSecurityWarning(r, sourceName, SecurityEventMultipleHeaders, "multiple single-IP headers received - possible spoofing attempt",
			"header", failure.headerName,
			"header_count", failure.headerCount,
		)
		e.config.metrics.RecordExtractionFailure(sourceName.String())
		return &MultipleHeadersError{
			ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: sourceName},
			HeaderCount:     failure.headerCount,
			HeaderName:      failure.headerName,
			RemoteAddr:      failure.remoteAddr,
		}
	case failureUntrustedProxy:
		e.config.metrics.RecordSecurityEvent(SecurityEventUntrustedProxy)
		e.logSecurityWarning(r, sourceName, SecurityEventUntrustedProxy, "request received from untrusted proxy while single-header source is present",
			"header", failure.headerName,
		)
		e.config.metrics.RecordExtractionFailure(sourceName.String())
		return &ProxyValidationError{
			ExtractionError:   ExtractionError{Err: ErrUntrustedProxy, Source: sourceName},
			Chain:             failure.chain,
			TrustedProxyCount: failure.trustedProxyCount,
			MinTrustedProxies: failure.minTrustedProxies,
			MaxTrustedProxies: failure.maxTrustedProxies,
		}
	case failureInvalidClientIP:
		e.recordInvalidClientIPDisposition(failure.clientIPDisposition)
		e.config.metrics.RecordExtractionFailure(sourceName.String())
		return &InvalidIPError{
			ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: sourceName},
			ExtractedIP:     failure.extractedIP,
		}
	default:
		return &ExtractionError{Err: ErrInvalidIP, Source: sourceName}
	}
}

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

func adaptForwardedParseError(err error, source Source, extractor *Extractor) error {
	if chainErr := adaptChainLengthError(err, source, extractor); chainErr != nil {
		return chainErr
	}

	return &ExtractionError{
		Err:    fmt.Errorf("%w: %w", ErrInvalidForwardedHeader, err),
		Source: source,
	}
}

func adaptXFFParseError(err error, source Source, extractor *Extractor) error {
	if chainErr := adaptChainLengthError(err, source, extractor); chainErr != nil {
		return chainErr
	}

	return err
}

func adaptChainLengthError(err error, source Source, extractor *Extractor) error {
	var chainErr *chainTooLongParseError
	if !errors.As(err, &chainErr) {
		return nil
	}

	extractor.config.metrics.RecordSecurityEvent(SecurityEventChainTooLong)

	return &ChainTooLongError{
		ExtractionError: ExtractionError{Err: ErrChainTooLong, Source: source},
		ChainLength:     chainErr.ChainLength,
		MaxLength:       chainErr.MaxLength,
	}
}

func (e *Extractor) validateProxyCount(trustedCount int) error {
	err := validateProxyCountPolicy(trustedCount, e.proxy)
	if err == nil {
		return nil
	}

	switch {
	case errors.Is(err, ErrNoTrustedProxies):
		e.config.metrics.RecordSecurityEvent(SecurityEventNoTrustedProxies)
		return ErrNoTrustedProxies
	case errors.Is(err, ErrTooFewTrustedProxies):
		e.config.metrics.RecordSecurityEvent(SecurityEventTooFewTrustedProxies)
		return ErrTooFewTrustedProxies
	case errors.Is(err, ErrTooManyTrustedProxies):
		e.config.metrics.RecordSecurityEvent(SecurityEventTooManyTrustedProxies)
		return ErrTooManyTrustedProxies
	default:
		return err
	}
}

func (e *Extractor) recordInvalidClientIPDisposition(disposition clientIPDisposition) {
	switch disposition {
	case clientIPInvalid:
		e.config.metrics.RecordSecurityEvent(SecurityEventInvalidIP)
	case clientIPReserved:
		e.config.metrics.RecordSecurityEvent(SecurityEventReservedIP)
	case clientIPPrivate:
		e.config.metrics.RecordSecurityEvent(SecurityEventPrivateIP)
	}
}

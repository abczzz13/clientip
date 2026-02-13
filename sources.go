package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
)

const (
	// SourceForwarded resolves from the RFC7239 Forwarded header.
	SourceForwarded = "forwarded"
	// SourceXForwardedFor resolves from the X-Forwarded-For header.
	SourceXForwardedFor = "x_forwarded_for"
	// SourceXRealIP resolves from the X-Real-IP header.
	SourceXRealIP = "x_real_ip"
	// SourceRemoteAddr resolves from Request.RemoteAddr.
	SourceRemoteAddr = "remote_addr"
)

type extractionResult struct {
	IP                netip.Addr
	TrustedProxyCount int
	DebugInfo         *ChainDebugInfo
	Source            string
}

type sourceExtractor interface {
	Extract(ctx context.Context, r *http.Request) (extractionResult, error)

	Name() string
}

func requestPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	return r.URL.Path
}

func (e *Extractor) logSecurityWarning(ctx context.Context, r *http.Request, sourceName, event, msg string, attrs ...any) {
	baseAttrs := []any{
		"event", event,
		"source", sourceName,
		"path", requestPath(r),
		"remote_addr", r.RemoteAddr,
	}

	baseAttrs = append(baseAttrs, attrs...)
	e.config.logger.WarnContext(ctx, msg, baseAttrs...)
}

func proxyValidationWarningDetails(err error) (event, msg string, ok bool) {
	switch {
	case errors.Is(err, ErrNoTrustedProxies):
		return securityEventNoTrustedProxies, "no trusted proxies found in request chain", true
	case errors.Is(err, ErrTooFewTrustedProxies):
		return securityEventTooFewTrustedProxies, "trusted proxy count below configured minimum", true
	case errors.Is(err, ErrTooManyTrustedProxies):
		return securityEventTooManyTrustedProxies, "trusted proxy count exceeds configured maximum", true
	default:
		return "", "", false
	}
}

func (e *Extractor) logProxyValidationWarning(ctx context.Context, r *http.Request, sourceName string, err error) {
	event, msg, ok := proxyValidationWarningDetails(err)
	if !ok {
		return
	}

	var proxyErr *ProxyValidationError
	if errors.As(err, &proxyErr) {
		e.logSecurityWarning(ctx, r, sourceName, event, msg,
			"trusted_proxy_count", proxyErr.TrustedProxyCount,
			"min_trusted_proxies", proxyErr.MinTrustedProxies,
			"max_trusted_proxies", proxyErr.MaxTrustedProxies,
		)
		return
	}

	e.logSecurityWarning(ctx, r, sourceName, event, msg)
}

func (e *Extractor) extractChainSource(
	ctx context.Context,
	r *http.Request,
	sourceName string,
	headerValues []string,
	chainForUntrusted string,
	untrustedProxyMessage string,
	chainTooLongMessage string,
	parseValues func([]string) ([]string, error),
	handleParseError func(error),
) (extractionResult, error) {
	if len(e.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseIP(r.RemoteAddr)
		if !e.isTrustedProxy(remoteIP) {
			e.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			e.logSecurityWarning(ctx, r, sourceName, securityEventUntrustedProxy, untrustedProxyMessage)
			e.config.metrics.RecordExtractionFailure(sourceName)
			return extractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: sourceName,
				},
				Chain:             chainForUntrusted,
				TrustedProxyCount: 0,
				MinTrustedProxies: e.config.minTrustedProxies,
				MaxTrustedProxies: e.config.maxTrustedProxies,
			}
		}
	}

	parts, err := parseValues(headerValues)
	if err != nil {
		if errors.Is(err, ErrChainTooLong) {
			var chainErr *ChainTooLongError
			if errors.As(err, &chainErr) {
				e.logSecurityWarning(ctx, r, sourceName, securityEventChainTooLong, chainTooLongMessage,
					"chain_length", chainErr.ChainLength,
					"max_length", chainErr.MaxLength,
				)
			} else {
				e.logSecurityWarning(ctx, r, sourceName, securityEventChainTooLong, chainTooLongMessage)
			}
		}

		if handleParseError != nil {
			handleParseError(err)
		}

		e.config.metrics.RecordExtractionFailure(sourceName)
		return extractionResult{}, err
	}

	ip, trustedCount, debugInfo, err := e.clientIPFromChainWithDebug(sourceName, parts)
	if err != nil {
		e.logProxyValidationWarning(ctx, r, sourceName, err)
		e.config.metrics.RecordExtractionFailure(sourceName)
		return extractionResult{}, err
	}

	e.config.metrics.RecordExtractionSuccess(sourceName)
	result := extractionResult{
		IP:                ip,
		TrustedProxyCount: trustedCount,
		Source:            sourceName,
	}

	if e.config.debugMode {
		result.DebugInfo = debugInfo
	}

	return result, nil
}

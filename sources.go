package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
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

type forwardedForSource struct {
	extractor *Extractor
}

type forwardedSource struct {
	extractor *Extractor
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

	if len(s.extractor.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseIP(r.RemoteAddr)
		if !s.extractor.isTrustedProxy(remoteIP) {
			chain := strings.Join(forwardedValues, ", ")
			s.extractor.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventUntrustedProxy, "request received from untrusted proxy while Forwarded is present")
			s.extractor.config.metrics.RecordExtractionFailure(s.Name())
			return extractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: s.Name(),
				},
				Chain:             chain,
				TrustedProxyCount: 0,
				MinTrustedProxies: s.extractor.config.minTrustedProxies,
				MaxTrustedProxies: s.extractor.config.maxTrustedProxies,
			}
		}
	}

	parts, err := s.extractor.parseForwardedValues(forwardedValues)
	if err != nil {
		if errors.Is(err, ErrChainTooLong) {
			var chainErr *ChainTooLongError
			if errors.As(err, &chainErr) {
				s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventChainTooLong, "Forwarded chain exceeds configured maximum length",
					"chain_length", chainErr.ChainLength,
					"max_length", chainErr.MaxLength,
				)
			} else {
				s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventChainTooLong, "Forwarded chain exceeds configured maximum length")
			}
		}

		if errors.Is(err, ErrInvalidForwardedHeader) {
			s.extractor.config.metrics.RecordSecurityEvent(securityEventMalformedForwarded)
			s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventMalformedForwarded, "malformed Forwarded header received", "parse_error", err.Error())
		}

		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, err
	}

	ip, trustedCount, debugInfo, err := s.extractor.clientIPFromChainWithDebug(s.Name(), parts)
	if err != nil {
		s.extractor.logProxyValidationWarning(ctx, r, s.Name(), err)

		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, err
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	result := extractionResult{
		IP:                ip,
		TrustedProxyCount: trustedCount,
		Source:            s.Name(),
	}

	if s.extractor.config.debugMode {
		result.DebugInfo = debugInfo
	}

	return result, nil
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

	if len(s.extractor.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseIP(r.RemoteAddr)
		if !s.extractor.isTrustedProxy(remoteIP) {
			chain := xffValues[0]
			s.extractor.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventUntrustedProxy, "request received from untrusted proxy while X-Forwarded-For is present")
			s.extractor.config.metrics.RecordExtractionFailure(s.Name())
			return extractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: s.Name(),
				},
				Chain:             chain,
				TrustedProxyCount: 0,
				MinTrustedProxies: s.extractor.config.minTrustedProxies,
				MaxTrustedProxies: s.extractor.config.maxTrustedProxies,
			}
		}
	}

	parts, err := s.extractor.parseXFFValues(xffValues)
	if err != nil {
		if errors.Is(err, ErrChainTooLong) {
			var chainErr *ChainTooLongError
			if errors.As(err, &chainErr) {
				s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventChainTooLong, "X-Forwarded-For chain exceeds configured maximum length",
					"chain_length", chainErr.ChainLength,
					"max_length", chainErr.MaxLength,
				)
			} else {
				s.extractor.logSecurityWarning(ctx, r, s.Name(), securityEventChainTooLong, "X-Forwarded-For chain exceeds configured maximum length")
			}
		}
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, err
	}

	ip, trustedCount, debugInfo, err := s.clientIPFromXFFWithDebug(parts)
	if err != nil {
		s.extractor.logProxyValidationWarning(ctx, r, s.Name(), err)

		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return extractionResult{}, err
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	result := extractionResult{
		IP:                ip,
		TrustedProxyCount: trustedCount,
		Source:            s.Name(),
	}

	if s.extractor.config.debugMode {
		result.DebugInfo = debugInfo
	}

	return result, nil
}

func (s *forwardedForSource) clientIPFromXFFWithDebug(parts []string) (netip.Addr, int, *ChainDebugInfo, error) {
	return s.extractor.clientIPFromChainWithDebug(s.Name(), parts)
}

type singleHeaderSource struct {
	extractor  *Extractor
	headerName string
	sourceName string
}

func (s *singleHeaderSource) Name() string {
	return s.sourceName
}

func (s *singleHeaderSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	headerValues := r.Header.Values(s.headerName)
	if len(headerValues) == 0 {
		return extractionResult{}, &ExtractionError{
			Err:    ErrSourceUnavailable,
			Source: s.Name(),
		}
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
		return extractionResult{}, &ExtractionError{
			Err:    ErrSourceUnavailable,
			Source: s.Name(),
		}
	}

	if len(s.extractor.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseIP(r.RemoteAddr)
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
	extractor *Extractor
}

func (s *remoteAddrSource) Name() string {
	return SourceRemoteAddr
}

func (s *remoteAddrSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	if r.RemoteAddr == "" {
		return extractionResult{}, &ExtractionError{
			Err:    ErrSourceUnavailable,
			Source: s.Name(),
		}
	}

	ip := parseIP(r.RemoteAddr)
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

type chainedSource struct {
	extractor *Extractor
	sources   []sourceExtractor
	name      string
}

func newChainedSource(extractor *Extractor, sources ...sourceExtractor) *chainedSource {
	names := make([]string, len(sources))
	for i, s := range sources {
		names[i] = s.Name()
	}
	return &chainedSource{
		extractor: extractor,
		sources:   sources,
		name:      "chained[" + strings.Join(names, ",") + "]",
	}
}

func newForwardedForSource(extractor *Extractor) sourceExtractor {
	return &forwardedForSource{extractor: extractor}
}

func newForwardedSource(extractor *Extractor) sourceExtractor {
	return &forwardedSource{extractor: extractor}
}

func newSingleHeaderSource(extractor *Extractor, headerName string) sourceExtractor {
	return &singleHeaderSource{
		extractor:  extractor,
		headerName: headerName,
		sourceName: NormalizeSourceName(headerName),
	}
}

func newRemoteAddrSource(extractor *Extractor) sourceExtractor {
	return &remoteAddrSource{extractor: extractor}
}

func (c *chainedSource) Extract(ctx context.Context, r *http.Request) (extractionResult, error) {
	var lastErr error
	for _, source := range c.sources {
		// Check if context has been cancelled before attempting next source
		if ctx.Err() != nil {
			return extractionResult{}, ctx.Err()
		}

		result, err := source.Extract(ctx, r)
		if err == nil {
			if result.Source == "" {
				result.Source = source.Name()
			}
			return result, nil
		}

		if c.isTerminalError(err) {
			return extractionResult{}, err
		}

		lastErr = err
	}
	return extractionResult{}, lastErr
}

func (c *chainedSource) isTerminalError(err error) bool {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	if errors.Is(err, ErrSourceUnavailable) {
		return false
	}

	if c.extractor.config.securityMode == SecurityModeLax {
		return false
	}

	return errors.Is(err, ErrInvalidIP) ||
		errors.Is(err, ErrMultipleXFFHeaders) ||
		errors.Is(err, ErrMultipleSingleIPHeaders) ||
		errors.Is(err, ErrUntrustedProxy) ||
		errors.Is(err, ErrNoTrustedProxies) ||
		errors.Is(err, ErrTooFewTrustedProxies) ||
		errors.Is(err, ErrTooManyTrustedProxies) ||
		errors.Is(err, ErrChainTooLong) ||
		errors.Is(err, ErrInvalidForwardedHeader)
}

func (c *chainedSource) Name() string {
	return c.name
}

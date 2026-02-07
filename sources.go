package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
)

const (
	SourceXForwardedFor = "x_forwarded_for"
	SourceXRealIP       = "x_real_ip"
	SourceRemoteAddr    = "remote_addr"
)

type ExtractionResult struct {
	IP                netip.Addr
	TrustedProxyCount int
	DebugInfo         *ChainDebugInfo
	Source            string
}

type Source interface {
	Extract(ctx context.Context, r *http.Request) (ExtractionResult, error)

	Name() string
}

type forwardedForSource struct {
	extractor *Extractor
}

func requestPath(r *http.Request) string {
	if r.URL == nil {
		return ""
	}
	return r.URL.Path
}

func (s *forwardedForSource) logSecurityWarning(ctx context.Context, r *http.Request, event, msg string, attrs ...any) {
	baseAttrs := []any{
		"event", event,
		"source", s.Name(),
		"path", requestPath(r),
		"remote_addr", r.RemoteAddr,
	}

	baseAttrs = append(baseAttrs, attrs...)
	s.extractor.config.logger.WarnContext(ctx, msg, baseAttrs...)
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

func (s *forwardedForSource) logProxyValidationWarning(ctx context.Context, r *http.Request, err error) {
	event, msg, ok := proxyValidationWarningDetails(err)
	if !ok {
		return
	}

	var proxyErr *ProxyValidationError
	if errors.As(err, &proxyErr) {
		s.logSecurityWarning(ctx, r, event, msg,
			"trusted_proxy_count", proxyErr.TrustedProxyCount,
			"min_trusted_proxies", proxyErr.MinTrustedProxies,
			"max_trusted_proxies", proxyErr.MaxTrustedProxies,
		)
		return
	}

	s.logSecurityWarning(ctx, r, event, msg)
}

func (s *forwardedForSource) Name() string {
	return SourceXForwardedFor
}

func (s *forwardedForSource) Extract(ctx context.Context, r *http.Request) (ExtractionResult, error) {
	xffValues := r.Header.Values("X-Forwarded-For")

	if len(xffValues) == 0 {
		return ExtractionResult{}, &ExtractionError{
			Err:    ErrInvalidIP,
			Source: s.Name(),
		}
	}

	if len(xffValues) > 1 {
		s.extractor.config.metrics.RecordSecurityEvent(securityEventMultipleHeaders)
		s.logSecurityWarning(ctx, r, securityEventMultipleHeaders, "multiple X-Forwarded-For headers received - possible spoofing attempt",
			"header_count", len(xffValues),
		)
		return ExtractionResult{}, &MultipleHeadersError{
			ExtractionError: ExtractionError{
				Err:    ErrMultipleXFFHeaders,
				Source: s.Name(),
			},
			HeaderCount: len(xffValues),
			RemoteAddr:  r.RemoteAddr,
		}
	}

	if len(s.extractor.config.trustedProxyCIDRs) > 0 {
		remoteIP := parseIP(r.RemoteAddr)
		if !s.extractor.isTrustedProxy(remoteIP) {
			s.extractor.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			s.logSecurityWarning(ctx, r, securityEventUntrustedProxy, "request received from untrusted proxy while X-Forwarded-For is present")
			s.extractor.config.metrics.RecordExtractionFailure(s.Name())
			return ExtractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: s.Name(),
				},
				XFF:               xffValues[0],
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
				s.logSecurityWarning(ctx, r, securityEventChainTooLong, "X-Forwarded-For chain exceeds configured maximum length",
					"chain_length", chainErr.ChainLength,
					"max_length", chainErr.MaxLength,
				)
			} else {
				s.logSecurityWarning(ctx, r, securityEventChainTooLong, "X-Forwarded-For chain exceeds configured maximum length")
			}
		}
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return ExtractionResult{}, err
	}

	ip, trustedCount, debugInfo, err := s.clientIPFromXFFWithDebug(parts)
	if err != nil {
		s.logProxyValidationWarning(ctx, r, err)

		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return ExtractionResult{}, err
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	result := ExtractionResult{
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
	if len(parts) == 0 {
		return netip.Addr{}, 0, nil, &ExtractionError{
			Err:    ErrInvalidIP,
			Source: s.Name(),
		}
	}

	analysis, err := s.extractor.analyzeChain(parts)

	// Only allocate debug info if debug mode is enabled
	var debugInfo *ChainDebugInfo
	if s.extractor.config.debugMode {
		debugInfo = &ChainDebugInfo{
			FullChain:      parts,
			ClientIndex:    analysis.clientIndex,
			TrustedIndices: analysis.trustedIndices,
		}
	}

	if err != nil {
		return netip.Addr{}, analysis.trustedCount, debugInfo, &ProxyValidationError{
			ExtractionError: ExtractionError{
				Err:    err,
				Source: s.Name(),
			},
			XFF:               strings.Join(parts, ", "),
			TrustedProxyCount: analysis.trustedCount,
			MinTrustedProxies: s.extractor.config.minTrustedProxies,
			MaxTrustedProxies: s.extractor.config.maxTrustedProxies,
		}
	}

	clientIPStr := parts[analysis.clientIndex]
	clientIP := parseIP(clientIPStr)

	if !s.extractor.isPlausibleClientIP(clientIP) {
		return netip.Addr{}, analysis.trustedCount, debugInfo, &InvalidIPError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: s.Name(),
			},
			XFF:            strings.Join(parts, ", "),
			ExtractedIP:    clientIPStr,
			Index:          analysis.clientIndex,
			TrustedProxies: analysis.trustedCount,
		}
	}

	return normalizeIP(clientIP), analysis.trustedCount, debugInfo, nil
}

type singleHeaderSource struct {
	extractor  *Extractor
	headerName string
	sourceName string
}

func (s *singleHeaderSource) Name() string {
	return s.sourceName
}

func (s *singleHeaderSource) Extract(ctx context.Context, r *http.Request) (ExtractionResult, error) {
	headerValue := r.Header.Get(s.headerName)
	if headerValue == "" {
		return ExtractionResult{}, &ExtractionError{
			Err:    ErrInvalidIP,
			Source: s.Name(),
		}
	}

	ip := parseIP(headerValue)
	if !s.extractor.isPlausibleClientIP(ip) {
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return ExtractionResult{}, &InvalidIPError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: s.Name(),
			},
			ExtractedIP: headerValue,
		}
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	return ExtractionResult{IP: normalizeIP(ip), Source: s.Name()}, nil
}

type remoteAddrSource struct {
	extractor *Extractor
}

func (s *remoteAddrSource) Name() string {
	return SourceRemoteAddr
}

func (s *remoteAddrSource) Extract(ctx context.Context, r *http.Request) (ExtractionResult, error) {
	if r.RemoteAddr == "" {
		return ExtractionResult{}, &ExtractionError{
			Err:    ErrInvalidIP,
			Source: s.Name(),
		}
	}

	ip := parseIP(r.RemoteAddr)
	if !s.extractor.isPlausibleClientIP(ip) {
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return ExtractionResult{}, &RemoteAddrError{
			ExtractionError: ExtractionError{
				Err:    ErrInvalidIP,
				Source: s.Name(),
			},
			RemoteAddr: r.RemoteAddr,
		}
	}

	s.extractor.config.metrics.RecordExtractionSuccess(s.Name())
	return ExtractionResult{IP: normalizeIP(ip), Source: s.Name()}, nil
}

type chainedSource struct {
	extractor *Extractor
	sources   []Source
	name      string
}

func newChainedSource(extractor *Extractor, sources ...Source) *chainedSource {
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

func newForwardedForSource(extractor *Extractor) Source {
	return &forwardedForSource{extractor: extractor}
}

func newSingleHeaderSource(extractor *Extractor, headerName string) Source {
	return &singleHeaderSource{
		extractor:  extractor,
		headerName: headerName,
		sourceName: NormalizeSourceName(headerName),
	}
}

func newRemoteAddrSource(extractor *Extractor) Source {
	return &remoteAddrSource{extractor: extractor}
}

func (c *chainedSource) Extract(ctx context.Context, r *http.Request) (ExtractionResult, error) {
	var lastErr error
	for _, source := range c.sources {
		// Check if context has been cancelled before attempting next source
		if ctx.Err() != nil {
			return ExtractionResult{}, ctx.Err()
		}

		result, err := source.Extract(ctx, r)
		if err == nil {
			if result.Source == "" {
				result.Source = source.Name()
			}
			return result, nil
		}

		if c.isTerminalError(err) {
			return ExtractionResult{}, err
		}

		lastErr = err
	}
	return ExtractionResult{}, lastErr
}

func (c *chainedSource) isTerminalError(err error) bool {
	if c.extractor.config.securityMode == SecurityModeLax {
		return false
	}

	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}

	return errors.Is(err, ErrMultipleXFFHeaders) ||
		errors.Is(err, ErrUntrustedProxy) ||
		errors.Is(err, ErrNoTrustedProxies) ||
		errors.Is(err, ErrTooFewTrustedProxies) ||
		errors.Is(err, ErrTooManyTrustedProxies) ||
		errors.Is(err, ErrChainTooLong)
}

func (c *chainedSource) Name() string {
	return c.name
}

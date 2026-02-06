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
		s.extractor.config.metrics.RecordSecurityEvent("multiple_headers")
		path := ""
		if r.URL != nil {
			path = r.URL.Path
		}
		s.extractor.config.logger.WarnContext(ctx, "multiple X-Forwarded-For headers received - possible spoofing attempt",
			"header_count", len(xffValues),
			"path", path,
			"remote_addr", r.RemoteAddr)
		return ExtractionResult{}, &MultipleHeadersError{
			ExtractionError: ExtractionError{
				Err:    ErrMultipleXFFHeaders,
				Source: s.Name(),
			},
			HeaderCount: len(xffValues),
			RemoteAddr:  r.RemoteAddr,
		}
	}

	parts, err := s.extractor.parseXFFValues(xffValues)
	if err != nil {
		s.extractor.config.metrics.RecordExtractionFailure(s.Name())
		return ExtractionResult{}, err
	}

	ip, trustedCount, debugInfo, err := s.clientIPFromXFFWithDebug(parts)
	if err != nil {
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
		errors.Is(err, ErrProxyCountOutOfRange) ||
		errors.Is(err, ErrChainTooLong) ||
		errors.Is(err, ErrUntrustedProxy) ||
		errors.Is(err, ErrNoTrustedProxies)
}

func (c *chainedSource) Name() string {
	return c.name
}

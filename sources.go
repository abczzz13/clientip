package clientip

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/netip"
	"net/textproto"
	"strings"
)

type sourceKind uint8

const (
	sourceInvalid sourceKind = iota
	sourceForwarded
	sourceXForwardedFor
	sourceXRealIP
	sourceRemoteAddr
	sourceHeader
)

const (
	builtinSourceNameForwarded     = "forwarded"
	builtinSourceNameXForwardedFor = "x_forwarded_for"
	builtinSourceNameXRealIP       = "x_real_ip"
	builtinSourceNameRemoteAddr    = "remote_addr"
)

var (
	// SourceForwarded resolves from the RFC7239 Forwarded header.
	SourceForwarded = Source{kind: sourceForwarded}
	// SourceXForwardedFor resolves from the X-Forwarded-For header.
	SourceXForwardedFor = Source{kind: sourceXForwardedFor}
	// SourceXRealIP resolves from the X-Real-IP header.
	SourceXRealIP = Source{kind: sourceXRealIP}
	// SourceRemoteAddr resolves from Request.RemoteAddr.
	SourceRemoteAddr = Source{kind: sourceRemoteAddr}
)

// Source identifies one extraction source in priority order.
//
// Use built-in constants for standard sources and HeaderSource for custom
// headers.
type Source struct {
	kind       sourceKind
	headerName string
}

func builtinSource(kind sourceKind) Source {
	return Source{kind: kind}
}

// HeaderSource returns a source backed by a custom HTTP header name.
func HeaderSource(name string) Source {
	return sourceFromString(name)
}

func canonicalSource(source Source) Source {
	switch source.kind {
	case sourceForwarded, sourceXForwardedFor, sourceXRealIP, sourceRemoteAddr:
		return source
	case sourceHeader:
		return sourceFromString(source.headerName)
	default:
		return Source{}
	}
}

func sourceFromString(name string) Source {
	raw := strings.TrimSpace(name)
	if raw == "" {
		return Source{}
	}

	switch normalizeSourceName(raw) {
	case builtinSourceNameForwarded:
		return builtinSource(sourceForwarded)
	case builtinSourceNameXForwardedFor:
		return builtinSource(sourceXForwardedFor)
	case builtinSourceNameXRealIP:
		return builtinSource(sourceXRealIP)
	case builtinSourceNameRemoteAddr:
		return builtinSource(sourceRemoteAddr)
	default:
		return Source{kind: sourceHeader, headerName: textproto.CanonicalMIMEHeaderKey(raw)}
	}
}

// canonicalizeSources ensures every source is in canonical form.
//
// Sources stored in config.sourcePriority are always canonical; callers must
// not rely on name()/valid()/headerKey() re-canonicalizing on each call.
func canonicalizeSources(sources []Source) []Source {
	resolved := make([]Source, len(sources))
	for i, source := range sources {
		resolved[i] = canonicalSource(source)
	}
	return resolved
}

func (s Source) String() string {
	return s.name()
}

// Equal reports whether two sources represent the same canonical source.
func (s Source) Equal(other Source) bool {
	return canonicalSource(s) == canonicalSource(other)
}

func (s Source) name() string {
	switch s.kind {
	case sourceForwarded:
		return builtinSourceNameForwarded
	case sourceXForwardedFor:
		return builtinSourceNameXForwardedFor
	case sourceXRealIP:
		return builtinSourceNameXRealIP
	case sourceRemoteAddr:
		return builtinSourceNameRemoteAddr
	case sourceHeader:
		return normalizeSourceName(s.headerName)
	default:
		return ""
	}
}

func (s Source) valid() bool {
	if s.kind == sourceHeader {
		return s.headerName != ""
	}

	return s.kind == sourceForwarded ||
		s.kind == sourceXForwardedFor ||
		s.kind == sourceXRealIP ||
		s.kind == sourceRemoteAddr
}

func (s Source) headerKey() (string, bool) {
	switch s.kind {
	case sourceForwarded:
		return "Forwarded", true
	case sourceXForwardedFor:
		return "X-Forwarded-For", true
	case sourceXRealIP:
		return "X-Real-IP", true
	case sourceRemoteAddr, sourceInvalid:
		return "", false
	default:
		return s.headerName, true
	}
}

func (s Source) marshalValue() string {
	if s.kind == sourceHeader {
		return s.headerName
	}

	return s.String()
}

// MarshalText returns a stable text form for the source.
//
// Built-in sources serialize as canonical identifiers. Custom header sources
// serialize as canonical MIME header names so they can be losslessly parsed.
func (s Source) MarshalText() ([]byte, error) {
	return []byte(s.marshalValue()), nil
}

// UnmarshalText parses a source from a built-in alias or header name.
func (s *Source) UnmarshalText(text []byte) error {
	if s == nil {
		return errors.New("clientip.Source: UnmarshalText on nil pointer")
	}

	*s = sourceFromString(string(text))
	return nil
}

// MarshalJSON returns the source as a JSON string.
func (s Source) MarshalJSON() ([]byte, error) {
	return json.Marshal(s.marshalValue())
}

// UnmarshalJSON parses a source from a JSON string.
func (s *Source) UnmarshalJSON(data []byte) error {
	if s == nil {
		return errors.New("clientip.Source: UnmarshalJSON on nil pointer")
	}

	var raw string
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}

	*s = sourceFromString(raw)
	return nil
}

type extractionResult struct {
	IP                netip.Addr
	TrustedProxyCount int
	DebugInfo         *ChainDebugInfo
	Source            Source
}

type sourceExtractor interface {
	Extract(ctx context.Context, r *http.Request) (extractionResult, error)

	Name() string
	Source() Source
}

func requestPath(r *http.Request) string {
	if r == nil || r.URL == nil {
		return ""
	}

	return r.URL.Path
}

func (e *Extractor) logSecurityWarning(ctx context.Context, r *http.Request, source Source, event, msg string, attrs ...any) {
	remoteAddr := ""
	if r != nil {
		remoteAddr = r.RemoteAddr
	}

	baseAttrs := []any{
		"event", event,
		"source", source.String(),
		"path", requestPath(r),
		"remote_addr", remoteAddr,
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

func (e *Extractor) logProxyValidationWarning(ctx context.Context, r *http.Request, source Source, err error) {
	event, msg, ok := proxyValidationWarningDetails(err)
	if !ok {
		return
	}

	var proxyErr *ProxyValidationError
	if errors.As(err, &proxyErr) {
		e.logSecurityWarning(ctx, r, source, event, msg,
			"trusted_proxy_count", proxyErr.TrustedProxyCount,
			"min_trusted_proxies", proxyErr.MinTrustedProxies,
			"max_trusted_proxies", proxyErr.MaxTrustedProxies,
		)
		return
	}

	e.logSecurityWarning(ctx, r, source, event, msg)
}

func (e *Extractor) extractChainSource(
	ctx context.Context,
	r *http.Request,
	source Source,
	headerValues []string,
	chainForUntrusted func() string,
	untrustedProxyMessage string,
	chainTooLongMessage string,
	parseValues func([]string) ([]string, error),
	handleParseError func(error),
) (extractionResult, error) {
	if len(e.config.trustedProxyCIDRs) > 0 {
		remoteAddr := ""
		if r != nil {
			remoteAddr = r.RemoteAddr
		}

		remoteIP := parseRemoteAddr(remoteAddr)
		if !e.isTrustedProxy(remoteIP) {
			chain := ""
			if chainForUntrusted != nil {
				chain = chainForUntrusted()
			}

			e.config.metrics.RecordSecurityEvent(securityEventUntrustedProxy)
			e.logSecurityWarning(ctx, r, source, securityEventUntrustedProxy, untrustedProxyMessage)
			e.config.metrics.RecordExtractionFailure(source.String())
			return extractionResult{}, &ProxyValidationError{
				ExtractionError: ExtractionError{
					Err:    ErrUntrustedProxy,
					Source: source,
				},
				Chain:             chain,
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
				e.logSecurityWarning(ctx, r, source, securityEventChainTooLong, chainTooLongMessage,
					"chain_length", chainErr.ChainLength,
					"max_length", chainErr.MaxLength,
				)
			} else {
				e.logSecurityWarning(ctx, r, source, securityEventChainTooLong, chainTooLongMessage)
			}
		}

		if handleParseError != nil {
			handleParseError(err)
		}

		e.config.metrics.RecordExtractionFailure(source.String())
		return extractionResult{}, err
	}

	ip, trustedCount, debugInfo, err := e.clientIPFromChainWithDebug(source, parts)
	if err != nil {
		e.logProxyValidationWarning(ctx, r, source, err)
		e.config.metrics.RecordExtractionFailure(source.String())
		return extractionResult{}, err
	}

	e.config.metrics.RecordExtractionSuccess(source.String())
	result := extractionResult{
		IP:                ip,
		TrustedProxyCount: trustedCount,
		Source:            source,
	}

	if e.config.debugMode {
		result.DebugInfo = debugInfo
	}

	return result, nil
}

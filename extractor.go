package clientip

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/textproto"
)

// Extractor resolves client IP information from HTTP requests and
// framework-agnostic request inputs.
//
// Extractor instances are safe for concurrent reuse.
type Extractor struct {
	config          *config
	sources         []configuredSource
	clientIP        clientIPPolicy
	proxy           proxyPolicy
	extractViewFunc func(requestView) (Extraction, error)
}

type configuredSource struct {
	source         Source
	name           string
	unavailableErr *ExtractionError
	chain          chainExtractor
	single         singleHeaderExtractor
	remote         remoteAddrExtractor
}

// New creates an Extractor from a Config.
func New(public Config) (*Extractor, error) {
	cfg, err := configFromPublic(public)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	extractor := &Extractor{
		config: cfg,
		clientIP: clientIPPolicy{
			AllowPrivateIPs:             cfg.allowPrivateIPs,
			AllowReservedClientPrefixes: cfg.allowReservedClientPrefixes,
		},
		proxy: proxyPolicy{
			TrustedProxyCIDRs: cfg.trustedProxyCIDRs,
			TrustedProxyMatch: cfg.trustedProxyMatch,
			MinTrustedProxies: cfg.minTrustedProxies,
			MaxTrustedProxies: cfg.maxTrustedProxies,
		},
	}
	extractor.sources = extractor.buildConfiguredSources(cfg.sourcePriority)

	return extractor, nil
}

// Extract resolves client IP and metadata for the request.
func (e *Extractor) Extract(r *http.Request) (Extraction, error) {
	if r == nil {
		return Extraction{}, ErrNilRequest
	}

	if len(e.config.sourceHeaderKeys) == 0 {
		if ctx := r.Context(); ctx.Err() != nil {
			return Extraction{}, ctx.Err()
		}
		return e.extractFromRemoteAddr(r.RemoteAddr)
	}

	return e.extractRequestView(requestViewFromRequest(r))
}

// ExtractAddr resolves only the client IP address.
func (e *Extractor) ExtractAddr(r *http.Request) (netip.Addr, error) {
	extraction, err := e.Extract(r)
	if err != nil {
		return netip.Addr{}, err
	}

	return extraction.IP, nil
}

// ExtractInput resolves client IP and metadata from framework-agnostic request
// input.
func (e *Extractor) ExtractInput(input Input) (Extraction, error) {
	ctx := requestInputContext(input)
	if err := ctx.Err(); err != nil {
		return Extraction{}, err
	}

	if len(e.config.sourceHeaderKeys) == 0 {
		return e.extractFromRemoteAddr(input.RemoteAddr)
	}

	return e.extractRequestView(requestViewFromInput(input))
}

// ExtractInputAddr resolves only the client IP address from framework-agnostic
// request input.
func (e *Extractor) ExtractInputAddr(input Input) (netip.Addr, error) {
	extraction, err := e.ExtractInput(input)
	if err != nil {
		return netip.Addr{}, err
	}

	return extraction.IP, nil
}

func (e *Extractor) extractRequestView(r requestView) (Extraction, error) {
	if err := r.context().Err(); err != nil {
		return Extraction{}, err
	}

	if e.extractViewFunc != nil {
		result, err := e.extractViewFunc(r)
		if err != nil && !result.Source.valid() {
			result.Source = sourceValueFromError(err)
		}
		return result, err
	}

	for i := range e.sources {
		source := &e.sources[i]
		if i > 0 {
			if err := r.context().Err(); err != nil {
				return Extraction{}, err
			}
		}

		var (
			result Extraction
			err    error
		)

		switch source.source.kind {
		case sourceForwarded:
			result, err = e.extractChainSource(
				r,
				source,
				"Forwarded chain exceeds configured maximum length",
				"request received from untrusted proxy while Forwarded is present",
				func(err error) {
					if !errors.Is(err, ErrInvalidForwardedHeader) {
						return
					}
					e.config.metrics.RecordSecurityEvent(SecurityEventMalformedForwarded)
					e.logSecurityWarning(r, source.source, SecurityEventMalformedForwarded, "malformed Forwarded header received", "parse_error", err.Error())
				},
			)
		case sourceXForwardedFor:
			result, err = e.extractChainSource(
				r,
				source,
				"X-Forwarded-For chain exceeds configured maximum length",
				"request received from untrusted proxy while X-Forwarded-For is present",
				nil,
			)
		case sourceRemoteAddr:
			result, err = e.extractRemoteAddrSource(r, source)
		default:
			result, err = e.extractSingleHeaderSource(r, source)
		}
		if err == nil {
			return result, nil
		}

		if sourceIsTerminalError(err) {
			if !result.Source.valid() {
				result.Source = sourceValueFromError(err)
			}
			return result, err
		}

		if i == len(e.sources)-1 {
			if !result.Source.valid() {
				result.Source = sourceValueFromError(err)
			}
			return result, err
		}
	}

	return Extraction{}, ErrSourceUnavailable
}

func (e *Extractor) extractFromRemoteAddr(remoteAddr string) (Extraction, error) {
	source := builtinSource(sourceRemoteAddr)
	result, failure := remoteAddrExtractor{clientIPPolicy: e.clientIP}.extract(remoteAddr, source)
	if failure != nil {
		if failure.kind != failureSourceUnavailable {
			e.recordInvalidClientIPDisposition(failure.clientIPDisposition)
			e.config.metrics.RecordExtractionFailure(source.String())
		}
		err := adaptRemoteAddrFailure(failure, source)
		result.Source = sourceValueFromError(err)
		return result, err
	}

	e.config.metrics.RecordExtractionSuccess(source.String())
	return result, nil
}

func (e *Extractor) buildConfiguredSources(sources []Source) []configuredSource {
	configured := make([]configuredSource, len(sources))
	for i, source := range sources {
		source := source
		headerName, _ := sourceHeaderKey(source)
		if headerName != "" {
			headerName = textproto.CanonicalMIMEHeaderKey(headerName)
		}

		configuredSource := configuredSource{
			source:         source,
			name:           source.String(),
			unavailableErr: &ExtractionError{Err: ErrSourceUnavailable, Source: source},
		}

		switch source.kind {
		case sourceForwarded:
			configuredSource.chain = chainExtractor{policy: chainPolicy{
				headerName: headerName,
				parseValues: func(values []string) ([]string, error) {
					parts, err := parseForwardedValues(values, e.config.maxChainLength)
					if err != nil {
						return nil, adaptForwardedParseError(err, source, e)
					}
					return parts, nil
				},
				parseClientIP:     parseChainIP,
				clientIP:          e.clientIP,
				trustedProxy:      e.proxy,
				selection:         e.config.chainSelection,
				collectDebugInfo:  e.config.debugMode,
				untrustedChainSep: ", ",
			}}
		case sourceXForwardedFor:
			configuredSource.chain = chainExtractor{policy: chainPolicy{
				headerName: headerName,
				parseValues: func(values []string) ([]string, error) {
					parts, err := parseXFFValues(values, e.config.maxChainLength)
					if err != nil {
						return nil, adaptXFFParseError(err, source, e)
					}
					return parts, nil
				},
				parseClientIP:     parseIP,
				clientIP:          e.clientIP,
				trustedProxy:      e.proxy,
				selection:         e.config.chainSelection,
				collectDebugInfo:  e.config.debugMode,
				untrustedChainSep: ", ",
			}}
		case sourceRemoteAddr:
			configuredSource.remote = remoteAddrExtractor{clientIPPolicy: e.clientIP}
		default:
			configuredSource.single = singleHeaderExtractor{policy: singleHeaderPolicy{
				headerName:   headerName,
				clientIP:     e.clientIP,
				trustedProxy: e.proxy,
			}}
		}

		configured[i] = configuredSource
	}

	return configured
}

func sourceValueFromError(err error) Source {
	var sourceErr interface{ SourceValue() Source }
	if errors.As(err, &sourceErr) {
		return sourceErr.SourceValue()
	}

	return Source{}
}

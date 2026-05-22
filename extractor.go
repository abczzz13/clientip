package clientip

import (
	"errors"
	"fmt"
	"net/http"
	"net/textproto"
)

// extractor resolves client IP information from HTTP requests and
// framework-agnostic request inputs.
//
// extractor instances are safe for concurrent reuse.
type extractor struct {
	config  *config
	sources []configuredSource
}

type configuredSource struct {
	source         Source
	name           string
	unavailableErr *ExtractionError
	chain          chainExtractor
	single         singleHeaderExtractor
	remote         remoteAddrExtractor
}

// newExtractor creates an extractor from a options.
//
// newExtractor applies default values, normalizes prefixes and sources,
// validates the resulting configuration, and returns an extractor safe for
// concurrent reuse.
func newExtractor(public options) (*extractor, error) {
	cfg, err := configFromPublic(public)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	extractor := &extractor{config: cfg}
	extractor.sources = extractor.buildConfiguredSources(cfg.sourcePriority)

	return extractor, nil
}

// Extract resolves client IP and metadata for the request.
//
// Configured sources are attempted in order. ErrSourceUnavailable allows the
// next source to run; malformed headers, proxy-trust failures, chain limits,
// invalid client IPs, and context errors are terminal.
func (e *extractor) Extract(r *http.Request) (Extraction, error) {
	if r == nil {
		return Extraction{}, ErrNilRequest
	}

	// sourceHeaderKeys is empty only when the configured sources contain no
	// header-based source. Validation guarantees at least one configured
	// source, so reaching this branch means the only configured source is
	// SourceRemoteAddr.
	if len(e.config.sourceHeaderKeys) == 0 {
		if ctx := r.Context(); ctx.Err() != nil {
			return Extraction{}, ctx.Err()
		}
		return e.extractFromRemoteAddr(r.RemoteAddr)
	}

	return e.extractRequestView(requestViewFromRequest(r))
}

// ExtractInput resolves client IP and metadata from framework-agnostic request
// input.
//
// It follows the same source ordering and terminal-error rules as Extract.
func (e *extractor) ExtractInput(input Input) (Extraction, error) {
	ctx := requestInputContext(input)
	if err := ctx.Err(); err != nil {
		return Extraction{}, err
	}

	// See Extract: an empty sourceHeaderKeys means SourceRemoteAddr is the
	// only configured source.
	if len(e.config.sourceHeaderKeys) == 0 {
		return e.extractFromRemoteAddr(input.RemoteAddr)
	}

	return e.extractRequestView(requestViewFromInput(input))
}

func (e *extractor) extractRequestView(r requestView) (Extraction, error) {
	if err := r.context().Err(); err != nil {
		return Extraction{}, err
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
				result.Source = source.source
			}
			return result, err
		}

		if i == len(e.sources)-1 {
			if !result.Source.valid() {
				result.Source = source.source
			}
			return result, err
		}
	}

	return Extraction{}, ErrSourceUnavailable
}

func (e *extractor) extractFromRemoteAddr(remoteAddr string) (Extraction, error) {
	source := builtinSource(sourceRemoteAddr)
	result, failure := remoteAddrExtractor{clientIPPolicy: e.config.clientIP}.extract(remoteAddr, source)
	if failure != nil {
		err := adaptRemoteAddrFailure(failure, source)
		result.Source = source
		return result, err
	}

	return result, nil
}

func (e *extractor) buildConfiguredSources(sources []Source) []configuredSource {
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
				clientIP:          e.config.clientIP,
				trustedProxy:      e.config.proxy,
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
				clientIP:          e.config.clientIP,
				trustedProxy:      e.config.proxy,
				selection:         e.config.chainSelection,
				collectDebugInfo:  e.config.debugMode,
				untrustedChainSep: ", ",
			}}
		case sourceRemoteAddr:
			configuredSource.remote = remoteAddrExtractor{clientIPPolicy: e.config.clientIP}
		default:
			configuredSource.single = singleHeaderExtractor{policy: singleHeaderPolicy{
				headerName:   headerName,
				clientIP:     e.config.clientIP,
				trustedProxy: e.config.proxy,
			}}
		}

		configured[i] = configuredSource
	}

	return configured
}

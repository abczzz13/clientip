package clientip

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

// Extractor resolves client IP information from HTTP requests.
//
// Extractor instances are safe for concurrent reuse.
type Extractor struct {
	config *config
	source sourceExtractor
}

// New creates an Extractor from one or more Option builders.
func New(opts ...Option) (*Extractor, error) {
	cfg, err := configFromOptions(opts...)
	if err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	extractor := &Extractor{config: cfg}
	extractor.source = extractor.buildSourceChain(cfg)

	return extractor, nil
}

func (e *Extractor) buildSourceChain(cfg *config) sourceExtractor {
	sources := make([]sourceExtractor, 0, len(cfg.sourcePriority))
	for _, sourceName := range cfg.sourcePriority {
		resolvedSourceName := canonicalSourceName(sourceName)
		var source sourceExtractor
		switch resolvedSourceName {
		case SourceForwarded:
			source = newForwardedSource(e)
		case SourceXForwardedFor:
			source = newForwardedForSource(e)
		case SourceXRealIP:
			source = newSingleHeaderSource(e, "X-Real-IP")
		case SourceRemoteAddr:
			source = newRemoteAddrSource(e)
		default:
			// Assume it's a custom header name.
			source = newSingleHeaderSource(e, sourceName)
		}
		sources = append(sources, source)
	}

	return newChainedSource(e, sources...)
}

func canonicalSourceName(sourceName string) string {
	switch NormalizeSourceName(sourceName) {
	case SourceForwarded:
		return SourceForwarded
	case SourceXForwardedFor:
		return SourceXForwardedFor
	case SourceXRealIP:
		return SourceXRealIP
	case SourceRemoteAddr:
		return SourceRemoteAddr
	default:
		return sourceName
	}
}

// Extract resolves client IP and metadata for the request.
//
// When overrides are provided, they are merged left-to-right and applied only
// for this call.
func (e *Extractor) Extract(r *http.Request, overrides ...OverrideOptions) (Extraction, error) {
	activeExtractor := e
	activeSource := e.source

	if len(overrides) > 0 {
		effectiveConfig, err := e.config.withOverrides(overrides...)
		if err != nil {
			return Extraction{}, fmt.Errorf("invalid override options: %w", err)
		}

		if effectiveConfig != e.config {
			activeExtractor = &Extractor{config: effectiveConfig}
			activeExtractor.source = activeExtractor.buildSourceChain(effectiveConfig)
			activeSource = activeExtractor.source
		}
	}

	return activeExtractor.extractWithSource(activeSource, r)
}

// ExtractAddr resolves only the client IP address.
func (e *Extractor) ExtractAddr(r *http.Request, overrides ...OverrideOptions) (netip.Addr, error) {
	extraction, err := e.Extract(r, overrides...)
	if err != nil {
		return netip.Addr{}, err
	}

	return extraction.IP, nil
}

// ExtractWithOptions is a one-shot convenience helper.
//
// It constructs a temporary extractor from opts and resolves metadata for r.
func ExtractWithOptions(r *http.Request, opts ...Option) (Extraction, error) {
	extractor, err := New(opts...)
	if err != nil {
		return Extraction{}, err
	}

	return extractor.Extract(r)
}

// ExtractAddrWithOptions is a one-shot convenience helper.
//
// It constructs a temporary extractor from opts and resolves only the client
// IP address for r.
func ExtractAddrWithOptions(r *http.Request, opts ...Option) (netip.Addr, error) {
	extractor, err := New(opts...)
	if err != nil {
		return netip.Addr{}, err
	}

	return extractor.ExtractAddr(r)
}

func (e *Extractor) extractWithSource(source sourceExtractor, r *http.Request) (Extraction, error) {
	ctx := r.Context()

	extractionResult, err := source.Extract(ctx, r)
	sourceName := e.getSourceName(extractionResult, err)

	if err != nil {
		return Extraction{
			Source:            sourceName,
			TrustedProxyCount: extractionResult.TrustedProxyCount,
			DebugInfo:         extractionResult.DebugInfo,
		}, err
	}

	return Extraction{
		IP:                normalizeIP(extractionResult.IP),
		Source:            sourceName,
		TrustedProxyCount: extractionResult.TrustedProxyCount,
		DebugInfo:         extractionResult.DebugInfo,
	}, nil
}

func (e *Extractor) getSourceName(result extractionResult, err error) string {
	if err != nil {
		var sourceErr interface{ SourceName() string }
		if errors.As(err, &sourceErr) {
			return sourceErr.SourceName()
		}
		return ""
	}
	if result.Source != "" {
		return result.Source
	}
	return e.source.Name()
}

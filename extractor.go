package clientip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

// Extractor resolves client IP information from HTTP requests and
// framework-agnostic request inputs.
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
	for _, configuredSource := range cfg.sourcePriority {
		var source sourceExtractor
		switch configuredSource {
		case SourceForwarded:
			source = newForwardedSource(e)
		case SourceXForwardedFor:
			source = newForwardedForSource(e)
		case SourceXRealIP:
			source = newSingleHeaderSource(e, "X-Real-IP")
		case SourceRemoteAddr:
			source = newRemoteAddrSource(e)
		default:
			headerName, _ := configuredSource.headerKey()
			source = newSingleHeaderSource(e, headerName)
		}
		sources = append(sources, source)
	}

	return newChainedSource(e, sources...)
}

// Extract resolves client IP and metadata for the request.
//
// When call options are provided, they are applied left-to-right and applied only
// for this call.
func (e *Extractor) Extract(r *http.Request, callOpts ...CallOption) (Extraction, error) {
	if r == nil {
		return Extraction{}, ErrNilRequest
	}

	ctx := r.Context()

	if len(callOpts) == 0 {
		return e.extractWithSource(e.source, ctx, r)
	}

	activeExtractor, activeSource, err := e.prepareCall(callOpts...)
	if err != nil {
		return Extraction{}, err
	}

	return activeExtractor.extractWithSource(activeSource, ctx, r)
}

// ExtractAddr resolves only the client IP address.
func (e *Extractor) ExtractAddr(r *http.Request, callOpts ...CallOption) (netip.Addr, error) {
	extraction, err := e.Extract(r, callOpts...)
	if err != nil {
		return netip.Addr{}, err
	}

	return extraction.IP, nil
}

// ExtractFrom resolves client IP and metadata from framework-agnostic request
// input.
//
// When call options are provided, they are applied left-to-right and applied only
// for this call.
func (e *Extractor) ExtractFrom(input RequestInput, callOpts ...CallOption) (Extraction, error) {
	activeExtractor := e
	activeSource := e.source

	if len(callOpts) > 0 {
		var err error
		activeExtractor, activeSource, err = e.prepareCall(callOpts...)
		if err != nil {
			return Extraction{}, err
		}
	}

	ctx := requestInputContext(input)
	if err := ctx.Err(); err != nil {
		return Extraction{}, err
	}

	if len(activeExtractor.config.sourceHeaderKeys) == 0 {
		return activeExtractor.extractFromRemoteAddr(input.RemoteAddr)
	}

	req := requestFromInput(input, activeExtractor.config.sourceHeaderKeys)

	return activeExtractor.extractWithSource(activeSource, ctx, req)
}

// ExtractAddrFrom resolves only the client IP address from framework-agnostic
// request input.
func (e *Extractor) ExtractAddrFrom(input RequestInput, callOpts ...CallOption) (netip.Addr, error) {
	extraction, err := e.ExtractFrom(input, callOpts...)
	if err != nil {
		return netip.Addr{}, err
	}

	return extraction.IP, nil
}

func (e *Extractor) prepareCall(callOpts ...CallOption) (*Extractor, sourceExtractor, error) {
	activeExtractor := e
	activeSource := e.source

	if len(callOpts) == 0 {
		return activeExtractor, activeSource, nil
	}

	effectiveConfig, err := e.config.withCallOptions(callOpts...)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid call options: %w", err)
	}
	if effectiveConfig == e.config {
		return activeExtractor, activeSource, nil
	}

	activeExtractor = &Extractor{config: effectiveConfig}
	activeExtractor.source = activeExtractor.buildSourceChain(effectiveConfig)
	activeSource = activeExtractor.source

	return activeExtractor, activeSource, nil
}

func (e *Extractor) extractWithSource(source sourceExtractor, ctx context.Context, r *http.Request) (Extraction, error) {
	extractionResult, err := source.Extract(ctx, r)
	if err != nil {
		sourceName := e.getSourceName(extractionResult, err)
		return Extraction{
			Source:            sourceName,
			TrustedProxyCount: extractionResult.TrustedProxyCount,
			DebugInfo:         extractionResult.DebugInfo,
		}, err
	}

	sourceName := extractionResult.Source
	if sourceName == "" {
		sourceName = source.Name()
	}

	return Extraction{
		IP:                normalizeIP(extractionResult.IP),
		Source:            sourceName,
		TrustedProxyCount: extractionResult.TrustedProxyCount,
		DebugInfo:         extractionResult.DebugInfo,
	}, nil
}

func (e *Extractor) extractFromRemoteAddr(remoteAddr string) (Extraction, error) {
	result, err := e.extractRemoteAddr(remoteAddr)
	if err != nil {
		sourceName := e.getSourceName(result, err)
		return Extraction{
			Source:            sourceName,
			TrustedProxyCount: result.TrustedProxyCount,
			DebugInfo:         result.DebugInfo,
		}, err
	}

	return Extraction{
		IP:                normalizeIP(result.IP),
		Source:            result.Source,
		TrustedProxyCount: result.TrustedProxyCount,
		DebugInfo:         result.DebugInfo,
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

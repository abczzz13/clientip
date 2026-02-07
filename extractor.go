package clientip

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
)

type Extractor struct {
	config *Config
	source Source
}

func New(opts ...Option) (*Extractor, error) {
	cfg := defaultConfig()

	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("invalid option: %w", err)
		}
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("invalid configuration: %w", err)
	}

	extractor := &Extractor{config: cfg}

	sources := make([]Source, 0, len(cfg.sourcePriority))
	for _, sourceName := range cfg.sourcePriority {
		resolvedSourceName := canonicalSourceName(sourceName)
		var source Source
		switch resolvedSourceName {
		case SourceForwarded:
			source = newForwardedSource(extractor)
		case SourceXForwardedFor:
			source = newForwardedForSource(extractor)
		case SourceXRealIP:
			source = newSingleHeaderSource(extractor, "X-Real-IP")
		case SourceRemoteAddr:
			source = newRemoteAddrSource(extractor)
		default:
			// Assume it's a custom header name
			source = newSingleHeaderSource(extractor, sourceName)
		}
		sources = append(sources, source)
	}

	extractor.source = newChainedSource(extractor, sources...)

	return extractor, nil
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

func (e *Extractor) ExtractIP(r *http.Request) Result {
	ctx := r.Context()

	extractionResult, err := e.source.Extract(ctx, r)
	sourceName := e.getSourceName(extractionResult, err)

	if err != nil {
		return Result{
			IP:                netip.Addr{},
			Source:            sourceName,
			Err:               err,
			TrustedProxyCount: extractionResult.TrustedProxyCount,
			DebugInfo:         extractionResult.DebugInfo,
		}
	}

	return Result{
		IP:                normalizeIP(extractionResult.IP),
		Source:            sourceName,
		Err:               nil,
		TrustedProxyCount: extractionResult.TrustedProxyCount,
		DebugInfo:         extractionResult.DebugInfo,
	}
}

func (e *Extractor) getSourceName(result ExtractionResult, err error) string {
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

package clientip

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

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
	return &forwardedForSource{
		extractor:      extractor,
		unavailableErr: &ExtractionError{Err: ErrSourceUnavailable, Source: SourceXForwardedFor},
	}
}

func newForwardedSource(extractor *Extractor) sourceExtractor {
	return &forwardedSource{
		extractor:      extractor,
		unavailableErr: &ExtractionError{Err: ErrSourceUnavailable, Source: SourceForwarded},
	}
}

func newSingleHeaderSource(extractor *Extractor, headerName string) sourceExtractor {
	sourceName := NormalizeSourceName(headerName)
	return &singleHeaderSource{
		extractor:      extractor,
		headerName:     headerName,
		sourceName:     sourceName,
		unavailableErr: &ExtractionError{Err: ErrSourceUnavailable, Source: sourceName},
	}
}

func newRemoteAddrSource(extractor *Extractor) sourceExtractor {
	return &remoteAddrSource{
		extractor:      extractor,
		unavailableErr: &ExtractionError{Err: ErrSourceUnavailable, Source: SourceRemoteAddr},
	}
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

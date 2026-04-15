package clientip

import (
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
	config   *config
	source   sourceExtractor
	clientIP clientIPPolicy
	proxy    proxyPolicy
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
	extractor.source = extractor.buildSourceChain(cfg)

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

	return e.extractWithSource(e.source, requestViewFromRequest(r))
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

	return e.extractWithSource(e.source, requestViewFromInput(input))
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

func (e *Extractor) extractWithSource(source sourceExtractor, r requestView) (Extraction, error) {
	if err := r.context().Err(); err != nil {
		return Extraction{}, err
	}

	result, err := source.extract(r)
	if err != nil {
		fallbackSource := source.sourceInfo()
		if !result.Source.valid() {
			result.Source = fallbackSource
		}
		result.Source = e.getSource(result, err)
		return result, err
	}

	return result, nil
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
		result.Source = e.getSource(result, err)
		return result, err
	}

	e.config.metrics.RecordExtractionSuccess(source.String())
	return result, nil
}

// getSource resolves the authoritative source for a result.
//
// Precedence: error-embedded source > result source > extractor default.
func (e *Extractor) getSource(result Extraction, err error) Source {
	if err != nil {
		var sourceErr interface{ SourceValue() Source }
		if errors.As(err, &sourceErr) {
			return sourceErr.SourceValue()
		}
		return Source{}
	}
	if result.Source.valid() {
		return result.Source
	}
	return e.source.sourceInfo()
}

package clientip

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
)

var errNilResolverExtractor = errors.New("resolver extractor cannot be nil")

type resolverStateContextKey struct{}

type resolutionSlot struct {
	set   bool
	value Resolution
}

// resolverState caches strict and preferred resolutions for one request.
// The mutex is held during compute() to guarantee at-most-once extraction;
// concurrent callers on the same request block until the first completes.
type resolverState struct {
	mu        sync.Mutex
	strict    resolutionSlot
	preferred resolutionSlot
}

// PreferredFallback controls which explicit fallback ResolvePreferred applies
// after strict extraction fails.
type PreferredFallback uint8

const (
	// PreferredFallbackNone leaves ResolvePreferred without a fallback path.
	PreferredFallbackNone PreferredFallback = iota
	// PreferredFallbackRemoteAddr falls back to parsed RemoteAddr.
	PreferredFallbackRemoteAddr
	// PreferredFallbackStaticIP falls back to StaticFallbackIP.
	PreferredFallbackStaticIP
)

func (f PreferredFallback) valid() bool {
	return f == PreferredFallbackNone || f == PreferredFallbackRemoteAddr || f == PreferredFallbackStaticIP
}

// ResolverConfig configures Resolver preferred fallback behavior.
type ResolverConfig struct {
	// PreferredFallback selects which explicit fallback ResolvePreferred applies
	// after strict extraction fails.
	PreferredFallback PreferredFallback
	// StaticFallbackIP is required when PreferredFallback is
	// PreferredFallbackStaticIP.
	StaticFallbackIP netip.Addr
}

// Resolution captures a resolver result, including fallback metadata.
type Resolution struct {
	Extraction
	Err          error
	FallbackUsed bool
}

// OK reports whether the resolution produced a usable IP without error.
func (r Resolution) OK() bool {
	return r.Err == nil && r.IP.IsValid()
}

// Resolver orchestrates strict and preferred resolution on top of Extractor.
type Resolver struct {
	extractor *Extractor
	config    ResolverConfig
}

// NewResolver creates a Resolver for a reusable Extractor.
func NewResolver(extractor *Extractor, config ResolverConfig) (*Resolver, error) {
	if extractor == nil {
		return nil, fmt.Errorf("invalid resolver configuration: %w", errNilResolverExtractor)
	}

	config.StaticFallbackIP = normalizeIP(config.StaticFallbackIP)
	if !config.PreferredFallback.valid() {
		return nil, fmt.Errorf("invalid resolver configuration: unsupported preferred fallback %d", config.PreferredFallback)
	}

	switch config.PreferredFallback {
	case PreferredFallbackNone, PreferredFallbackRemoteAddr:
		if config.StaticFallbackIP.IsValid() {
			return nil, fmt.Errorf("invalid resolver configuration: StaticFallbackIP requires PreferredFallbackStaticIP")
		}
	case PreferredFallbackStaticIP:
		if !config.StaticFallbackIP.IsValid() {
			return nil, fmt.Errorf("invalid resolver configuration: PreferredFallbackStaticIP requires StaticFallbackIP")
		}
	}

	return &Resolver{extractor: extractor, config: config}, nil
}

// ResolveStrict resolves client IP information without fallback.
func (r *Resolver) ResolveStrict(req *http.Request) (*http.Request, Resolution) {
	if r == nil || r.extractor == nil {
		return req, Resolution{Err: errNilResolverExtractor}
	}
	if req == nil {
		return nil, Resolution{Err: ErrNilRequest}
	}

	req, state := requestWithResolverState(req)
	resolution := state.ResolveStrict(func() Resolution { return r.resolveStrictRequest(req) })
	return req, resolution
}

func (s *resolverState) ResolveStrict(compute func() Resolution) Resolution {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.strict.set {
		return s.strict.value
	}

	value := compute()
	s.strict = resolutionSlot{set: true, value: value}
	return value
}

func (s *resolverState) ResolvePreferred(
	computeStrict func() Resolution,
	shouldFallback func(Resolution) bool,
	fallback func(Resolution) (Resolution, bool),
) Resolution {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.preferred.set {
		return s.preferred.value
	}

	strict := s.strict.value
	if !s.strict.set {
		strict = computeStrict()
		s.strict = resolutionSlot{set: true, value: strict}
	}

	preferred := strict
	if shouldFallback != nil && shouldFallback(strict) && fallback != nil {
		if resolved, ok := fallback(strict); ok {
			preferred = resolved
		}
	}

	s.preferred = resolutionSlot{set: true, value: preferred}
	return preferred
}

func (s *resolverState) StrictValue() (Resolution, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.strict.set {
		return Resolution{}, false
	}

	return s.strict.value, true
}

func (s *resolverState) PreferredValue() (Resolution, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.preferred.set {
		return Resolution{}, false
	}

	return s.preferred.value, true
}

// ResolvePreferred resolves client IP information using the configured
// preferred fallback policy after strict extraction fails.
func (r *Resolver) ResolvePreferred(req *http.Request) (*http.Request, Resolution) {
	if r == nil || r.extractor == nil {
		return req, Resolution{Err: errNilResolverExtractor}
	}
	if req == nil {
		return nil, Resolution{Err: ErrNilRequest}
	}

	req, state := requestWithResolverState(req)
	preferred := state.ResolvePreferred(
		func() Resolution { return r.resolveStrictRequest(req) },
		func(strict Resolution) bool {
			return strict.Err != nil && !isResolverTerminalContextError(strict.Err)
		},
		func(Resolution) (Resolution, bool) { return r.preferredFallback(req.RemoteAddr) },
	)
	return req, preferred
}

// ResolveInputStrict resolves client IP information from framework-agnostic input without fallback.
func (r *Resolver) ResolveInputStrict(input Input) (Input, Resolution) {
	if r == nil || r.extractor == nil {
		return input, Resolution{Err: errNilResolverExtractor}
	}

	input, state := inputWithResolverState(input)
	resolution := state.ResolveStrict(func() Resolution { return r.resolveStrictInput(input) })
	return input, resolution
}

// ResolveInputPreferred resolves client IP information from framework-agnostic
// input using the configured preferred fallback policy after strict extraction
// fails.
func (r *Resolver) ResolveInputPreferred(input Input) (Input, Resolution) {
	if r == nil || r.extractor == nil {
		return input, Resolution{Err: errNilResolverExtractor}
	}

	input, state := inputWithResolverState(input)
	preferred := state.ResolvePreferred(
		func() Resolution { return r.resolveStrictInput(input) },
		func(strict Resolution) bool {
			return strict.Err != nil && !isResolverTerminalContextError(strict.Err)
		},
		func(Resolution) (Resolution, bool) { return r.preferredFallback(input.RemoteAddr) },
	)
	return input, preferred
}

// StrictResolutionFromContext returns the cached strict resolution, if present.
func StrictResolutionFromContext(ctx context.Context) (Resolution, bool) {
	state, ok := resolverStateFromContext(ctx)
	if !ok {
		return Resolution{}, false
	}

	return state.StrictValue()
}

// PreferredResolutionFromContext returns the cached preferred resolution, if present.
func PreferredResolutionFromContext(ctx context.Context) (Resolution, bool) {
	state, ok := resolverStateFromContext(ctx)
	if !ok {
		return Resolution{}, false
	}

	return state.PreferredValue()
}

func (r *Resolver) resolveStrictRequest(req *http.Request) Resolution {
	extraction, err := r.extractor.Extract(req)
	return Resolution{Extraction: extraction, Err: err}
}

func (r *Resolver) resolveStrictInput(input Input) Resolution {
	extraction, err := r.extractor.ExtractInput(input)
	return Resolution{Extraction: extraction, Err: err}
}

func (r *Resolver) preferredFallback(remoteAddr string) (Resolution, bool) {
	switch r.config.PreferredFallback {
	case PreferredFallbackRemoteAddr:
		ip, err := ParseRemoteAddr(remoteAddr)
		if err == nil {
			return Resolution{
				Extraction:   Extraction{IP: ip, Source: SourceRemoteAddr},
				FallbackUsed: true,
			}, true
		}
	case PreferredFallbackStaticIP:
		return Resolution{
			Extraction:   Extraction{IP: r.config.StaticFallbackIP, Source: SourceStaticFallback},
			FallbackUsed: true,
		}, true
	}

	return Resolution{}, false
}

func resolverStateFromContext(ctx context.Context) (*resolverState, bool) {
	if ctx == nil {
		return nil, false
	}

	state, ok := ctx.Value(resolverStateContextKey{}).(*resolverState)
	if !ok || state == nil {
		return nil, false
	}

	return state, true
}

func requestWithResolverState(req *http.Request) (*http.Request, *resolverState) {
	if state, ok := resolverStateFromContext(req.Context()); ok {
		return req, state
	}

	state := &resolverState{}
	return req.WithContext(context.WithValue(req.Context(), resolverStateContextKey{}, state)), state
}

func inputWithResolverState(input Input) (Input, *resolverState) {
	ctx := requestInputContext(input)
	if state, ok := resolverStateFromContext(ctx); ok {
		input.Context = ctx
		return input, state
	}

	state := &resolverState{}
	input.Context = context.WithValue(ctx, resolverStateContextKey{}, state)
	return input, state
}

func isResolverTerminalContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

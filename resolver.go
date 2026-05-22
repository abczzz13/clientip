package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
)

var errNilResolverExtractor = errors.New("resolver extractor cannot be nil")

type resultContextKey struct{}

// Fallback controls per-call operational fallback behavior.
type Fallback struct {
	mode     fallbackMode
	staticIP netip.Addr
}

type fallbackMode uint8

const (
	fallbackNone fallbackMode = iota
	fallbackRemoteAddr
	fallbackStaticIP
)

// NoFallback disables operational fallback.
func NoFallback() Fallback { return Fallback{mode: fallbackNone} }

// RemoteAddrFallback falls back to the connecting peer address.
func RemoteAddrFallback() Fallback { return Fallback{mode: fallbackRemoteAddr} }

// StaticFallback falls back to a configured static IP.
//
// Static fallback is a caller-supplied operational value. It is normalized, but
// not checked against the package's client-IP plausibility policy; callers that
// need a routable or policy-valid fallback should validate that before passing
// it here.
func StaticFallback(ip netip.Addr) Fallback {
	return Fallback{mode: fallbackStaticIP, staticIP: normalizeIP(ip)}
}

// FallbackReason describes why ResolveOperational used fallback.
type FallbackReason uint8

const (
	FallbackReasonNone FallbackReason = iota
	FallbackReasonUntrustedProxy
	FallbackReasonMalformedHeader
	FallbackReasonSourceUnavailable
	FallbackReasonInvalidIP
)

// String returns the stable label for r.
func (r FallbackReason) String() string {
	switch r {
	case FallbackReasonNone:
		return "none"
	case FallbackReasonUntrustedProxy:
		return "untrusted_proxy"
	case FallbackReasonMalformedHeader:
		return "malformed_header"
	case FallbackReasonSourceUnavailable:
		return "source_unavailable"
	case FallbackReasonInvalidIP:
		return "invalid_ip"
	default:
		return "unknown"
	}
}

// Result captures a resolver result, including fallback metadata.
type Result struct {
	// Extraction contains the IP and source metadata. It may still contain a
	// Source when Err is non-nil.
	Extraction

	// Err is the strict extraction error, or nil when strict extraction or
	// operational fallback produced a usable IP.
	Err error

	// FallbackUsed reports whether ResolveOperational returned a configured
	// fallback result instead of the strict extraction result.
	FallbackUsed bool

	// FallbackReason reports why operational fallback was used.
	FallbackReason FallbackReason
}

// OK reports whether the resolution produced a usable IP without error.
func (r Result) OK() bool {
	return r.Err == nil && r.IP.IsValid()
}

// IsValid reports whether the result contains a usable IP without error.
func (r Result) IsValid() bool { return r.OK() }

// Classify returns a coarse result kind suitable for policy and metrics labels.
func (r Result) Classify() ResultKind {
	if r.FallbackUsed {
		return ResultFallback
	}
	return ClassifyError(r.Err)
}

// Resolver resolves client IP information using the configured trust policy.
//
// Resolver instances are safe for concurrent reuse.
type Resolver struct {
	extractor *extractor
}

// New constructs a Resolver from options. With no options, the resolver uses a
// safe direct-connection configuration that only consults RemoteAddr.
func New(opts ...Option) (*Resolver, error) {
	public := options{}
	for _, opt := range opts {
		if opt == nil {
			continue
		}
		opt.applyOption(&public)
	}

	extractor, err := newExtractor(public)
	if err != nil {
		return nil, err
	}
	return &Resolver{extractor: extractor}, nil
}

// Resolve resolves client IP information without fallback.
func (r *Resolver) Resolve(req *http.Request) Result {
	if r == nil || r.extractor == nil {
		return Result{Err: errNilResolverExtractor}
	}
	if req == nil {
		result := Result{Err: ErrNilRequest}
		r.observe(context.Background(), result)
		return result
	}

	result := r.resolveStrictRequest(req)
	r.observe(req.Context(), result)
	return result
}

// ResolveOperational resolves client IP information with per-call best-effort
// fallback. When fallback succeeds, Err is nil and fallback metadata is set.
func (r *Resolver) ResolveOperational(req *http.Request, fallback Fallback) Result {
	if r == nil || r.extractor == nil {
		return Result{Err: errNilResolverExtractor}
	}
	if req == nil {
		result := Result{Err: ErrNilRequest}
		r.observe(context.Background(), result)
		return result
	}

	strict := r.resolveStrictRequest(req)
	result := strict
	if strict.Err != nil && !isResolverTerminalContextError(strict.Err) {
		if resolved, ok := r.applyFallback(req.RemoteAddr, fallback, strict.Err); ok {
			result = resolved
		}
	}
	r.observe(req.Context(), result)
	return result
}

// ResolveInput resolves client IP information from framework-agnostic input.
func (r *Resolver) ResolveInput(input Input) Result {
	if r == nil || r.extractor == nil {
		return Result{Err: errNilResolverExtractor}
	}
	result := r.resolveStrictInput(input)
	r.observe(requestInputContext(input), result)
	return result
}

// ResolveInputOperational resolves framework-agnostic input with per-call
// best-effort fallback.
func (r *Resolver) ResolveInputOperational(input Input, fallback Fallback) Result {
	if r == nil || r.extractor == nil {
		return Result{Err: errNilResolverExtractor}
	}
	strict := r.resolveStrictInput(input)
	result := strict
	if strict.Err != nil && !isResolverTerminalContextError(strict.Err) {
		if resolved, ok := r.applyFallback(input.RemoteAddr, fallback, strict.Err); ok {
			result = resolved
		}
	}
	r.observe(requestInputContext(input), result)
	return result
}

// ResolveHeaders resolves from plain http.Header and RemoteAddr values.
func (r *Resolver) ResolveHeaders(ctx context.Context, remoteAddr string, headers http.Header) Result {
	return r.ResolveInput(Input{Context: ctx, RemoteAddr: remoteAddr, Headers: headers})
}

// Middleware returns pass-through net/http middleware that stores Result in the
// request context. It never rejects; downstream handlers decide policy.
func (r *Resolver) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
			result := r.Resolve(req)
			ctx := context.WithValue(req.Context(), resultContextKey{}, result)
			next.ServeHTTP(w, req.WithContext(ctx))
		})
	}
}

// FromContext returns the Result attached by Middleware.
func FromContext(ctx context.Context) (Result, bool) {
	if ctx == nil {
		return Result{}, false
	}
	result, ok := ctx.Value(resultContextKey{}).(Result)
	return result, ok
}

func (r *Resolver) resolveStrictRequest(req *http.Request) Result {
	extraction, err := r.extractor.Extract(req)
	return Result{Extraction: extraction, Err: err}
}

func (r *Resolver) resolveStrictInput(input Input) Result {
	extraction, err := r.extractor.ExtractInput(input)
	return Result{Extraction: extraction, Err: err}
}

func (r *Resolver) observe(ctx context.Context, result Result) {
	if ctx == nil {
		ctx = context.Background()
	}
	r.extractor.config.observer.OnResolved(ctx, result)
}

func (r *Resolver) applyFallback(remoteAddr string, fallback Fallback, strictErr error) (Result, bool) {
	reason := fallbackReasonFromError(strictErr)
	switch fallback.mode {
	case fallbackRemoteAddr:
		ip, err := ParseRemoteAddr(remoteAddr)
		if err == nil {
			return Result{
				Extraction:     Extraction{IP: ip, Source: SourceRemoteAddr},
				FallbackUsed:   true,
				FallbackReason: reason,
			}, true
		}
	case fallbackStaticIP:
		ip := normalizeIP(fallback.staticIP)
		if ip.IsValid() {
			return Result{
				Extraction:     Extraction{IP: ip, Source: SourceStaticFallback},
				FallbackUsed:   true,
				FallbackReason: reason,
			}, true
		}
	}
	return Result{}, false
}

func fallbackReasonFromError(err error) FallbackReason {
	switch ClassifyError(err) {
	case ResultUntrusted:
		return FallbackReasonUntrustedProxy
	case ResultMalformed:
		return FallbackReasonMalformedHeader
	case ResultUnavailable:
		return FallbackReasonSourceUnavailable
	case ResultInvalid:
		return FallbackReasonInvalidIP
	default:
		return FallbackReasonNone
	}
}

func isResolverTerminalContextError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded)
}

// Package clientip provides secure client IP resolution from HTTP requests and
// framework-agnostic inputs with trusted proxy validation and explicit source
// modeling.
//
// # Choose The API
//
// Resolver is the primary integration-facing API. Construct one with New and
// functional options.
//
// Use Resolver when you want to:
//
//   - resolve once per request or Input
//   - reuse the result later from context
//   - choose between strict and operational semantics
//   - keep fallback behavior explicit at the call site
//
// Input is the framework-agnostic carrier for non-net/http integrations. It
// exists for frameworks that do not expose *http.Request directly while still
// preserving repeated header-line semantics. This matters because duplicate
// single-IP headers must be detected and chain headers must preserve the order
// in which repeated header lines arrived.
//
// ParseRemoteAddr and ClassifyError are small helpers for explicit fallback and
// policy code. ClassifyError keeps typed errors intact while providing a
// smaller ResultKind layer for middleware and policy branches.
//
// # Basic Usage
//
//	resolver, err := clientip.New(clientip.PresetLoopbackReverseProxy())
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
//	req.Header.Set("X-Forwarded-For", "8.8.8.8")
//
//	result := resolver.Resolve(req)
//	if result.Err != nil {
//	    log.Printf("resolve failed: %v", result.Err)
//	    return
//	}
//
//	fmt.Printf("Client IP: %s from %s\n", result.IP, result.Source)
//
// For net/http middleware, use Middleware and retrieve the Result with
// FromContext. Middleware is pass-through: downstream code decides whether to
// reject a request when Result.Err is non-nil.
//
// Framework-agnostic input is available through Resolver's input methods:
//
//	result := resolver.ResolveInput(clientip.Input{
//	    Context:    ctx,
//	    RemoteAddr: remoteAddr,
//	    Headers:    headerProvider,
//	})
//
// # Options, Sources, And Security
//
// New uses functional options. Zero options select safe defaults: RemoteAddr
// only, DefaultMaxChainLength, no-op logging, and no-op observation.
//
// Source values are public. Use the built-in extractor sources for
// request-derived extraction and HeaderSource for custom headers.
// SourceStaticFallback is a result-only sentinel that appears in Result.Source
// after a successful StaticFallback; it cannot be configured with WithSources.
//
// Resolver walks configured sources in order. Source-unavailable errors allow
// the next source to run, while malformed headers, proxy-trust failures, chain
// limits, and implausible client IPs remain terminal.
//
// Header-based sources require trusted upstream proxy ranges. Configure them
// with WithTrustedProxies, optionally using LoopbackProxyPrefixes,
// PrivateProxyPrefixes, LocalProxyPrefixes, or ProxyPrefixesFromAddrs.
// Count-only proxy trust is intentionally unsupported; WithMinTrustedProxies
// and WithMaxTrustedProxies validate the number of CIDR-trusted hops observed,
// but do not make a header source trusted on their own.
//
// ChainSelection applies to SourceForwarded and SourceXForwardedFor. The
// default RightmostUntrustedIP selects the nearest untrusted hop before the
// trailing trusted proxy suffix. LeftmostUntrustedIP selects the earliest
// untrusted entry and should only be used when trusted proxies are configured
// and the forwarded chain is produced or sanitized by those proxies.
//
// Operational fallback is explicit per call and useful for analytics/logging,
// but it is not suitable for authorization or trust-boundary enforcement.
// Context cancellation and deadline errors remain terminal. StaticFallback
// normalizes the supplied address but does not apply client-IP plausibility
// checks; callers should validate static fallback values when that matters.
//
// # Observability
//
// Logger records security warnings. Observer receives one event per resolver
// call on a valid Resolver and is the preferred metrics/tracing integration
// point.
//
// Security event labels are exported as SecurityEvent... constants so adapters
// can depend on stable names.
//
// Optional observer adapters live under clientip/observe/... so Prometheus,
// OpenTelemetry, and other integrations can evolve outside the dependency-free
// core package.
//
// Operational fallback is visible through Result.FallbackUsed,
// Result.FallbackReason, and Result.Classify().
package clientip

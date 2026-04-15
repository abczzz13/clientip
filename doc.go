// Package clientip provides secure client IP extraction from HTTP requests and
// framework-agnostic inputs with trusted proxy validation, explicit source
// modeling, and request-scoped resolver caching.
//
// # Choose The API
//
// Resolver is the primary integration-facing API.
//
// Use Resolver when you want to:
//
//   - resolve once per request or Input
//   - reuse the result later from context
//   - choose between strict and preferred semantics
//   - keep explicit fallback behavior on a separate layer from extraction
//
// Extractor remains the low-level strict primitive.
//
// Use Extractor when you want one direct extraction call without request-scoped
// caching or preferred fallback.
//
// Input is the framework-agnostic carrier for non-net/http integrations.
//
// ParseRemoteAddr and ClassifyError are small helpers for explicit fallback and
// policy code. ClassifyError keeps typed errors intact while providing a
// smaller ResultKind layer for middleware and policy branches.
//
// # Basic Usage
//
//	extractor, err := clientip.New(clientip.PresetLoopbackReverseProxy())
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
//	if err != nil {
//	    log.Fatal(err)
//	}
//
//	req, resolution := resolver.ResolveStrict(req)
//	if resolution.Err != nil {
//	    log.Printf("resolve failed: %v", resolution.Err)
//	    return
//	}
//
//	fmt.Printf("Client IP: %s from %s\n", resolution.IP, resolution.Source)
//
//	if cached, ok := clientip.StrictResolutionFromContext(req.Context()); ok {
//	    fmt.Printf("Cached client IP: %s\n", cached.IP)
//	}
//
// Framework-agnostic input is available through ExtractInput and Resolver's
// input methods. Resolver methods return the updated request or Input so cached
// resolution state can flow through the call path:
//
//	input, resolution := resolver.ResolveInputStrict(clientip.Input{
//	    Context:    ctx,
//	    RemoteAddr: remoteAddr,
//	    Path:       path,
//	    Headers:    headerProvider,
//	})
//	_ = input
//
// # Config, Sources, And Security
//
// Config stays flat in the current public API. Presets return Config values and
// can be tweaked before construction.
//
// Source values stay public and opaque. Use the built-in extractor sources for
// request-derived extraction, SourceStaticFallback for resolver static fallback
// results, and HeaderSource for custom headers.
//
// Extractor walks Config.Sources in order. Source-unavailable errors allow the
// next source to run, while malformed headers, proxy-trust failures, chain
// limits, and implausible client IPs remain terminal.
//
// Header-based sources require trusted upstream proxy ranges. Configure
// TrustedProxyPrefixes directly, optionally using LoopbackProxyPrefixes,
// PrivateProxyPrefixes, LocalProxyPrefixes, or ProxyPrefixesFromAddrs.
//
// Preferred resolver fallback is explicit and operationally useful, but it is
// not suitable for authorization or trust-boundary enforcement.
//
// # Observability
//
// Logger and Metrics remain separate public interfaces.
//
// Security event labels are exported as SecurityEvent... constants so adapters
// can depend on stable names.
//
// Preferred resolver fallback remains result-only in this phase. Inspect
// Resolution.FallbackUsed rather than expecting separate fallback log or metric
// signals.
package clientip

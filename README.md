# clientip

[![Go Reference](https://pkg.go.dev/badge/github.com/abczzz13/clientip.svg)](https://pkg.go.dev/github.com/abczzz13/clientip)
[![CI](https://github.com/abczzz13/clientip/actions/workflows/ci.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/ci.yml)
[![Security](https://github.com/abczzz13/clientip/actions/workflows/security.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/security.yml)
[![Fuzz](https://github.com/abczzz13/clientip/actions/workflows/fuzz.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/fuzz.yml)
[![Coverage](https://abczzz13.github.io/clientip/coverage.svg)](https://abczzz13.github.io/clientip/coverage/)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/abczzz13/clientip/badge)](https://scorecard.dev/viewer/?uri=github.com/abczzz13/clientip)
[![OpenSSF Best Practices](https://www.bestpractices.dev/projects/13032/badge)](https://www.bestpractices.dev/projects/13032)
[![License](https://img.shields.io/github/license/abczzz13/clientip)](LICENSE)

Secure client IP resolution for `net/http` and framework-agnostic request inputs with trusted proxy validation, explicit source modeling, and operational fallback.

## Contents

- [Stability](#stability)
- [Install](#install)
- [Quick Start](#quick-start)
- [Which API Should I Use?](#which-api-should-i-use)
- [Strict And Operational Resolution](#strict-and-operational-resolution)
- [Middleware](#middleware)
- [Framework-Agnostic Input](#framework-agnostic-input)
- [Common Deployments](#common-deployments)
- [Error Handling](#error-handling)
- [Presets](#presets)
- [Advanced Proxy Configuration](#advanced-proxy-configuration)
- [Observability](#observability)
- [Security Rules](#security-rules)
- [Threat Model](#threat-model)
- [Contributing](#contributing)

## Stability

Starting with `v0.1.0`, public APIs are intended to preserve compatibility according to Semantic Versioning.

Before a `v1.0.0` release, minor-version releases may still add APIs or refine behavior where SemVer allows.

## Install

```bash
go get github.com/abczzz13/clientip
```

Optional Prometheus adapter:

```bash
go get github.com/abczzz13/clientip/observe/prometheus
```

## Quick Start

Direct client-to-app traffic trusts only `RemoteAddr`:

```go
resolver, err := clientip.New()
if err != nil {
    log.Fatal(err)
}

result := resolver.Resolve(req)
if result.Err != nil {
    // fail closed for security-sensitive decisions
    return
}

fmt.Println(result.IP)
```

Loopback reverse proxy using `X-Forwarded-For`:

```go
resolver, err := clientip.New(clientip.PresetLoopbackReverseProxy())
```

Custom trusted proxy topology:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(prefixes...),
    clientip.WithSources(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
)
```

Header-based sources require trusted proxy prefixes. `clientip.New(clientip.WithSources(clientip.SourceXForwardedFor))` returns an error.

## Which API Should I Use?

- `Resolve(req)` is the strict API for authorization, ACLs, rate limits, abuse protection, and audit decisions.
- `ResolveOperational(req, fallback)` is for best-effort analytics and logging when a fallback value is acceptable.
- `Middleware()` stores the strict `Result` in request context and lets your handler decide whether to reject.
- `ResolveInput(input)` is for frameworks that do not expose `*http.Request` but can preserve repeated header-line values.
- `ResolveHeaders(ctx, remoteAddr, headers)` is the simplest non-`net/http` bridge when you already have `http.Header`.

## Strict And Operational Resolution

Use `Resolve` for security-sensitive decisions. It returns a `Result` with `Err` set when the request cannot be safely attributed.

Use `ResolveOperational` only for best-effort analytics/logging paths where fallback is acceptable:

```go
result := resolver.ResolveOperational(req, clientip.RemoteAddrFallback())
if result.FallbackUsed {
    fmt.Println(result.FallbackReason)
}
```

Operational fallback success clears `Err` and sets `FallbackUsed` plus `FallbackReason`. Do not use fallback results for authorization, ACLs, rate-limit identity, or other trust-boundary decisions.

`StaticFallback(ip)` is for caller-supplied operational defaults. The address is normalized but is not checked against client-IP plausibility rules, so validate it yourself if it must be routable or policy-valid.

## Middleware

`Middleware` is pass-through. It stores the strict `Result` in request context and never rejects by itself.
Rejection responses are intentionally application-owned so services can control
status codes, response bodies, headers, logging, and tracing.

```go
handler := resolver.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
    result, ok := clientip.FromContext(r.Context())
    if !ok || result.Err != nil {
        http.Error(w, "bad client IP", http.StatusBadRequest)
        return
    }
    _, _ = w.Write([]byte(result.IP.String()))
}))
```

## Framework-Agnostic Input

Use `Input` when a framework does not expose `*http.Request` directly. It exists to preserve repeated header-line semantics: duplicate single-IP headers must be detectable, and chain headers must preserve the order in which repeated header lines arrived. Header providers must therefore return repeated header lines as separate values.

```go
result := resolver.ResolveInput(clientip.Input{
    Context:    ctx,
    RemoteAddr: remoteAddr,
    Headers:    headersProvider,
})
```

For plain `http.Header` values:

```go
result := resolver.ResolveHeaders(ctx, remoteAddr, headers)
```

## Common Deployments

Direct app traffic should use the default resolver. It trusts only the connecting peer in `RemoteAddr`:

```go
resolver, err := clientip.New()
```

An app behind a same-host reverse proxy can use the loopback preset:

```go
resolver, err := clientip.New(clientip.PresetLoopbackReverseProxy())
```

An app behind an internal VM or private-network proxy can use the VM preset when those private ranges are the actual ingress boundary:

```go
resolver, err := clientip.New(clientip.PresetVMReverseProxy())
```

A CDN-origin service using a single-IP header must trust only the CDN peers that can connect to the origin:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedCDNPrefixes...),
    clientip.WithSources(clientip.HeaderSource("CF-Connecting-IP"), clientip.SourceRemoteAddr),
)
```

An ALB or reverse proxy that appends `X-Forwarded-For` should use a trusted-proxy range for the actual proxy-to-app path:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedIngressPrefixes...),
    clientip.WithSources(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
)
```

## Error Handling

For simple strict handling, check `Result.OK()` or `Result.Err`:

```go
result := resolver.Resolve(req)
if !result.OK() {
    switch result.Classify() {
    case clientip.ResultUntrusted, clientip.ResultMalformed:
        http.Error(w, "bad client IP", http.StatusBadRequest)
    default:
        http.Error(w, "client IP unavailable", http.StatusServiceUnavailable)
    }
    return
}
```

Use `errors.Is` for sentinel categories and `errors.As` for source-specific diagnostics:

```go
result := resolver.Resolve(req)
if errors.Is(result.Err, clientip.ErrUntrustedProxy) {
    // The peer was not in WithTrustedProxies while a header source was present.
}

var proxyErr *clientip.ProxyValidationError
if errors.As(result.Err, &proxyErr) {
    log.Printf("source=%s trusted=%d chain=%s", proxyErr.SourceName(), proxyErr.TrustedProxyCount, proxyErr.Chain)
}
```

## Presets

Generic option presets are available:

- `PresetDirectConnection()` trusts only `RemoteAddr`.
- `PresetLoopbackReverseProxy()` trusts loopback proxies and uses `X-Forwarded-For`, then `RemoteAddr`.
- `PresetVMReverseProxy()` trusts loopback/private proxy ranges and uses `X-Forwarded-For`, then `RemoteAddr`.

## Advanced Proxy Configuration

Provider and cloud proxy ranges need application-specific filtering before they are trusted. See [Trusted Proxy Configuration](docs/trusted-proxies.md) for provider range sources, CDN header examples, ALB/X-Forwarded-For guidance, and refresh workflow recommendations.

## Observability

Use `WithObserver` for result-level metrics/tracing:

```go
metrics, err := prometheus.New()
if err != nil {
    log.Fatal(err)
}

resolver, err := clientip.New(clientip.WithObserver(metrics))
```

Prometheus support lives in the optional `github.com/abczzz13/clientip/observe/prometheus` adapter module. OpenTelemetry and other adapters can use the same `Observer` interface without adding dependencies to the core package.

`Result.Classify()` returns a low-cardinality outcome suitable for metrics labels.

## Security Rules

- `RemoteAddr` is the only inherently trustworthy source.
- Forwarding headers are trusted only when the immediate peer is in `WithTrustedProxies`.
- The default chain algorithm is rightmost-untrusted before the trusted proxy suffix.
- Do not use operational fallback for security decisions.
- Count-only proxy trust is intentionally unsupported: `WithMinTrustedProxies` / `WithMaxTrustedProxies` validate CIDR-trusted hop counts and do not by themselves make a header source trusted.

## Threat Model

See [Threat Model](docs/threat-model.md) for security goals, trust assumptions, non-goals, failure behavior, and privacy notes.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, test commands, documentation expectations, and pull request guidance.

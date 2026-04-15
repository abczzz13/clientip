# clientip

[![CI](https://github.com/abczzz13/clientip/actions/workflows/ci.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abczzz13/clientip.svg)](https://pkg.go.dev/github.com/abczzz13/clientip)
[![License](https://img.shields.io/github/license/abczzz13/clientip)](LICENSE)

Secure client IP extraction for `net/http` and framework-agnostic request inputs with trusted proxy validation, explicit source modeling, and request-scoped resolver caching.

## Stability

This project is pre-`v1.0.0` and still before `v0.1.0`, so public APIs may change as the package evolves.
Any breaking changes are called out in `CHANGELOG.md`.

## Install

```bash
go get github.com/abczzz13/clientip
```

Optional Prometheus adapter:

```bash
go get github.com/abczzz13/clientip/prometheus
```

## Choose the API

- `Resolver` is the primary API. Use it when middleware, handlers, or framework adapters need to resolve the client IP once and reuse the result on the same request.
- `Extractor` is the low-level strict primitive. Use it when you only need one extraction call and do not need request-scoped caching or preferred fallback.
- `Input` is the framework-agnostic carrier for non-`net/http` integrations.
- `ParseRemoteAddr` and `ClassifyError` are small helpers for explicit fallback and policy code.

Construct an `Extractor` once and reuse it. Build a `Resolver` on top when you want strict or preferred request-scoped resolution.

## Quick Start

Use `Resolver.ResolveStrict` for security-sensitive or audit-oriented decisions.

```go
extractor, err := clientip.New(clientip.PresetLoopbackReverseProxy())
if err != nil {
    log.Fatal(err)
}

resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
if err != nil {
    log.Fatal(err)
}

req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
req.Header.Set("X-Forwarded-For", "8.8.8.8")

req, resolution := resolver.ResolveStrict(req)
if resolution.Err != nil {
    log.Fatal(resolution.Err)
}

fmt.Printf("Client IP: %s from %s\n", resolution.IP, resolution.Source)

if cached, ok := clientip.StrictResolutionFromContext(req.Context()); ok {
    fmt.Printf("Cached: %s\n", cached.IP)
}
```

## Preferred Resolution And Fallback

Use `Resolver.ResolvePreferred` when best-effort client IPs are operationally useful, such as rate limiting, analytics, or request tracing.

```go
extractor, err := clientip.New(clientip.Config{
    TrustedProxyPrefixes: clientip.LoopbackProxyPrefixes(),
    Sources:              []clientip.Source{clientip.SourceXForwardedFor},
})
if err != nil {
    log.Fatal(err)
}

resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{
    PreferredFallback: clientip.PreferredFallbackRemoteAddr,
})
if err != nil {
    log.Fatal(err)
}

req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}

_, resolution := resolver.ResolvePreferred(req)
if resolution.Err != nil {
    log.Fatal(resolution.Err)
}

fmt.Printf("Client IP: %s from %s (fallback=%t)\n", resolution.IP, resolution.Source, resolution.FallbackUsed)
```

Important fallback guidance:

- Preferred fallback is explicit and only lives on `Resolver`.
- `PreferredFallbackRemoteAddr` is operationally useful, but it is not equivalent to validated proxy-header extraction.
- Preferred resolution is not suitable for authorization, ACLs, or other trust-boundary decisions.
- Fallback observability is result-only in this phase. Inspect `Resolution.FallbackUsed`; do not expect a separate fallback metric or log event.

If you want a synthetic fallback value instead of `RemoteAddr`, set `ResolverConfig{PreferredFallback: clientip.PreferredFallbackStaticIP, StaticFallbackIP: ...}`. Successful static fallback reports `SourceStaticFallback`.

## Framework-Agnostic Input

Use `Input` with either `Extractor` or `Resolver` when your framework does not expose `*http.Request` directly.

```go
input := clientip.Input{
    Context:    ctx,
    RemoteAddr: remoteAddr,
    Path:       path,
    Headers:    headersProvider,
}

input, resolution := resolver.ResolveInputStrict(input)
if resolution.Err != nil {
    // handle error
}

if cached, ok := clientip.StrictResolutionFromContext(input.Context); ok {
    _ = cached
}
```

`Input.Headers` must preserve repeated header lines as separate slice entries. Do not merge duplicate lines into a single comma-joined string.

For `fasthttp`/Fiber style integrations:

```go
input := clientip.Input{
    Context:    c.UserContext(),
    RemoteAddr: c.Context().RemoteAddr().String(),
    Path:       c.Path(),
    Headers: clientip.HeaderValuesFunc(func(name string) []string {
        raw := c.Context().Request.Header.PeekAll(name)
        if len(raw) == 0 {
            return nil
        }

        values := make([]string, len(raw))
        for i, v := range raw {
            values[i] = string(v)
        }
        return values
    }),
}
```

## Presets

Presets return a flat `clientip.Config` that you can pass directly to `New` or tweak before construction.

- `PresetDirectConnection()` uses `RemoteAddr` only.
- `PresetLoopbackReverseProxy()` trusts loopback proxies and prioritizes `X-Forwarded-For` before `RemoteAddr`.
- `PresetVMReverseProxy()` trusts loopback and common private-network proxy ranges and prioritizes `X-Forwarded-For` before `RemoteAddr`.

```go
extractor, err := clientip.New(clientip.PresetVMReverseProxy())
if err != nil {
    log.Fatal(err)
}
```

If you need to tweak a preset, modify the returned config before calling `New`:

```go
cfg := clientip.PresetVMReverseProxy()
cfg.Sources = []clientip.Source{clientip.SourceForwarded, clientip.SourceRemoteAddr}

extractor, err := clientip.New(cfg)
if err != nil {
    log.Fatal(err)
}
```

Presets configure `Config`, not `ResolverConfig`. Preferred resolver fallback stays an explicit resolver-level choice.

## Config

`Config` stays flat in the current API.

Important fields:

- `TrustedProxyPrefixes []netip.Prefix`
- `MinTrustedProxies int`
- `MaxTrustedProxies int`
- `AllowPrivateIPs bool`
- `AllowedReservedClientPrefixes []netip.Prefix`
- `MaxChainLength int`
- `ChainSelection ChainSelection`
- `DebugInfo bool`
- `Sources []Source`
- `Logger Logger`
- `Metrics Metrics`

Useful helpers:

- `DefaultConfig()`
- `ParseCIDRs(...string)`
- `LoopbackProxyPrefixes()`
- `PrivateProxyPrefixes()`
- `LocalProxyPrefixes()`
- `ProxyPrefixesFromAddrs(...netip.Addr)`

Built-in extractor sources:

- `SourceForwarded`
- `SourceXForwardedFor`
- `SourceXRealIP`
- `SourceRemoteAddr`
- `HeaderSource(name)` for custom headers

Resolver-only result source:

- `SourceStaticFallback`

`Extractor` walks `Config.Sources` in order. `ErrSourceUnavailable` allows the next source to run, while security-significant failures remain terminal.

## Low-Level Extraction

Use `Extractor` directly when you want strict extraction without request-scoped caching or preferred fallback.

```go
extractor, err := clientip.New(clientip.DefaultConfig())
if err != nil {
    log.Fatal(err)
}

extraction, err := extractor.Extract(req)
if err != nil {
    log.Fatal(err)
}

fmt.Printf("Client IP: %s from %s\n", extraction.IP, extraction.Source)
```

Framework-agnostic extraction is also available:

```go
extraction, err := extractor.ExtractInput(input)
if err != nil {
    log.Fatal(err)
}
```

## Errors

Typed errors remain the detailed error surface:

```go
_, resolution := resolver.ResolveStrict(req)
if resolution.Err != nil {
    switch {
    case errors.Is(resolution.Err, clientip.ErrMultipleSingleIPHeaders):
    case errors.Is(resolution.Err, clientip.ErrInvalidForwardedHeader):
    case errors.Is(resolution.Err, clientip.ErrUntrustedProxy):
    case errors.Is(resolution.Err, clientip.ErrNoTrustedProxies):
    case errors.Is(resolution.Err, clientip.ErrTooFewTrustedProxies):
    case errors.Is(resolution.Err, clientip.ErrTooManyTrustedProxies):
    case errors.Is(resolution.Err, clientip.ErrInvalidIP):
    case errors.Is(resolution.Err, clientip.ErrSourceUnavailable):
    case errors.Is(resolution.Err, clientip.ErrNilRequest):
    }
}
```

`ClassifyError` provides a smaller policy-oriented layer on top of those typed errors:

```go
switch clientip.ClassifyError(resolution.Err) {
case clientip.ResultSuccess:
case clientip.ResultUnavailable:
case clientip.ResultInvalid:
case clientip.ResultUntrusted:
case clientip.ResultMalformed:
case clientip.ResultCanceled:
case clientip.ResultUnknown:
}
```

`ResultUnknown` covers non-nil errors outside the package's standard extraction and resolution categories.

Typed chain-related errors expose additional context:

- `ProxyValidationError`: `Chain`, `TrustedProxyCount`, `MinTrustedProxies`, `MaxTrustedProxies`
- `InvalidIPError`: `Chain`, `ExtractedIP`, `Index`, `TrustedProxies`
- `RemoteAddrError`: `RemoteAddr`
- `ChainTooLongError`: `ChainLength`, `MaxLength`

## Logging

Logging is disabled by default. Set `Config.Logger` to opt in.

```go
extractor, err := clientip.New(clientip.Config{
    Logger: slog.Default(),
})
```

The logger interface intentionally matches `slog.Logger.WarnContext`:

```go
type Logger interface {
    WarnContext(context.Context, string, ...any)
}
```

The context passed to logger calls comes from `req.Context()` (`Extract`) or `Input.Context` (`ExtractInput`).

Security event labels passed through `Metrics.RecordSecurityEvent(...)` are the stable exported `clientip.SecurityEvent...` constants.

## Prometheus Metrics

Construct Prometheus metrics explicitly and pass them through `Config.Metrics`.

```go
import clientipprom "github.com/abczzz13/clientip/prometheus"

metrics, err := clientipprom.New()
if err != nil {
    panic(err)
}

extractor, err := clientip.New(clientip.Config{Metrics: metrics})
if err != nil {
    panic(err)
}

resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
if err != nil {
    panic(err)
}
```

With a custom registerer:

```go
registry := prometheus.NewRegistry()

metrics, err := clientipprom.NewWithRegisterer(registry)
if err != nil {
    panic(err)
}
```

## Security Guidance

- Use `ResolveStrict` or `Extractor` for security-sensitive and audit-oriented behavior.
- Use `ResolvePreferred` only when explicit fallback is acceptable for operational reasons.
- Do not use preferred fallback for authorization, ACLs, or trust-boundary enforcement.
- Do not include multiple competing header-based sources for security decisions.
- Do not trust broad proxy CIDRs unless they are truly under your control.
- Header-based sources require `TrustedProxyPrefixes`.
- `LeftmostUntrustedIP` only makes sense when trusted proxy prefixes are configured.

## Compatibility

- Core module (`github.com/abczzz13/clientip`) supports Go `1.21+`.
- Optional Prometheus adapter (`github.com/abczzz13/clientip/prometheus`) has a minimum Go version of `1.21`; CI currently validates consumer mode on Go `1.21.x` and `1.26.x`.
- Prometheus client dependency in the adapter is pinned to `github.com/prometheus/client_golang v1.21.1`.

## Performance

- Extraction is `O(n)` in proxy-chain length.
- `Extractor` is safe for concurrent reuse.
- `Resolver` adds request-scoped caching on top of a reusable extractor.

Benchmark workflow with `just`:

```bash
# Capture a stable baseline (6 samples by default)
just bench-save before "BenchmarkExtract|BenchmarkChainAnalysis|BenchmarkParseIP"

# Make changes, then capture again
just bench-save after "BenchmarkExtract|BenchmarkChainAnalysis|BenchmarkParseIP"

# Compare with benchstat table output (delta + significance)
just bench-compare-saved before after
```

You can compare arbitrary files directly via `just bench-compare <before-file> <after-file>`.

## Maintainer Notes (Multi-Module)

- `prometheus/go.mod` intentionally does not use a local `replace` directive for `github.com/abczzz13/clientip`.
- For local co-development, create an uncommitted workspace with `go work init . ./prometheus`.
- Validate the adapter as a consumer with `GOWORK=off go -C prometheus test ./...`.
- `just` and CI validate the adapter in consumer mode by default (`GOWORK=off`); set `CLIENTIP_ADAPTER_GOWORK=auto` locally when you intentionally want workspace-mode adapter checks.
- Release in this order: tag root module `vX.Y.Z`, bump `prometheus/go.mod` to that version, then tag adapter module `prometheus/vX.Y.Z`.

## License

See `LICENSE`.

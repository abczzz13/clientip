# clientip

Secure client IP resolution for `net/http` and framework-agnostic request inputs with trusted proxy validation, explicit source modeling, and operational fallback.

## Stability

This project is pre-`v0.1.0`; public APIs may change before stabilization.

## Install

```bash
go get github.com/abczzz13/clientip
```

Optional Prometheus adapter:

```bash
go get github.com/abczzz13/clientip/prometheus
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

Use `Input` when a framework does not expose `*http.Request` directly. Header providers must preserve repeated header lines as separate values.

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

## Presets

Generic option presets are available:

- `PresetDirectConnection()` trusts only `RemoteAddr`.
- `PresetLoopbackReverseProxy()` trusts loopback proxies and uses `X-Forwarded-For`, then `RemoteAddr`.
- `PresetVMReverseProxy()` trusts loopback/private proxy ranges and uses `X-Forwarded-For`, then `RemoteAddr`.

Vendor-specific examples should explicitly pair the header with trusted peer ranges. For example, Cloudflare-style configuration should trust `CF-Connecting-IP` only when the immediate peer is in Cloudflare’s published CIDRs:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(cloudflarePrefixes...),
    clientip.WithSources(clientip.HeaderSource("CF-Connecting-IP"), clientip.SourceRemoteAddr),
)
```

AWS ALB append mode typically uses `X-Forwarded-For` with trusted VPC/ALB peer ranges:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(albOrVpcPrefixes...),
    clientip.WithSources(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
)
```

## Observability

Use `WithObserver` for result-level metrics/tracing:

```go
metrics, err := prometheus.New()
if err != nil {
    log.Fatal(err)
}

resolver, err := clientip.New(clientip.WithObserver(metrics))
```

`Result.Classify()` returns a low-cardinality outcome suitable for metrics labels.

## Security Rules

- `RemoteAddr` is the only inherently trustworthy source.
- Forwarding headers are trusted only when the immediate peer is in `WithTrustedProxies`.
- The default chain algorithm is rightmost-untrusted before the trusted proxy suffix.
- Do not use operational fallback for security decisions.
- Count-style proxy trust is brittle; prefer explicit CIDR-based trusted proxies.

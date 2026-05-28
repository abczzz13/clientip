# clientip

[![Go Reference](https://pkg.go.dev/badge/github.com/abczzz13/clientip.svg)](https://pkg.go.dev/github.com/abczzz13/clientip)
[![CI](https://github.com/abczzz13/clientip/actions/workflows/ci.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/ci.yml)
[![Security](https://github.com/abczzz13/clientip/actions/workflows/security.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/security.yml)
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
- [Observability](#observability)
- [Security Rules](#security-rules)
- [Contributing](#contributing)

## Stability

This project is pre-`v0.1.0`; public APIs may change before stabilization.

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

### Vendor And Cloud Proxy Ranges

When your service is behind a load balancer, CDN, or reverse proxy, `RemoteAddr` is usually that proxy, not the original client. The proxy may add headers such as `X-Forwarded-For`, `CF-Connecting-IP`, or other vendor-specific client IP headers. Those headers are plain HTTP headers and are spoofable unless the immediate peer is a proxy you trust to set or append them.

`WithTrustedProxies` is the allowlist for trusted ingress peers and, for chain headers, trusted forwarding hops. Single-IP headers such as `CF-Connecting-IP` are accepted only when the immediate `RemoteAddr` peer is trusted; chain headers such as `X-Forwarded-For` use the trusted suffix of proxy hops to select the client candidate. Only include ranges that can actually connect to your service. Provider IP ranges change over time, and dynamic range fetching introduces application-specific policy around refresh intervals, startup failure, caching, and regional filtering, so keep the trusted proxy ranges in your own configuration where they can follow your deployment process.

Recommended workflow:

- Fetch the ranges from the provider's official source.
- Filter to the product, region, VPC, subnet, load balancer, or CDN edge that can actually connect to your service.
- Parse the CIDRs with `clientip.ParseCIDRs`.
- Pass those prefixes to `clientip.WithTrustedProxies`.
- Refresh the ranges on your own deploy or configuration-management schedule.

Common provider range sources, useful as starting points before product/service/region filtering:

- AWS: `https://ip-ranges.amazonaws.com/ip-ranges.json`
- Azure: `https://www.microsoft.com/download/details.aspx?id=56519`
- Google Cloud: `https://www.gstatic.com/ipranges/cloud.json`
- Google Cloud default domains: `https://www.gstatic.com/ipranges/goog.json`
- Cloudflare: `https://www.cloudflare.com/ips-v4` and `https://www.cloudflare.com/ips-v6`
- Fastly: `https://api.fastly.com/public-ip-list`

Do not treat broad cloud-provider feeds as ready-to-use trusted proxy lists. Some feeds describe public service ranges and may not represent the immediate proxy peers that connect to your application.

Example configuration shape:

```go
trustedProxyCIDRs := []string{
    // Replace these documentation prefixes with your filtered proxy CIDRs.
    "203.0.113.0/24",
    "2001:db8:1234::/48",
}

trustedProxies, err := clientip.ParseCIDRs(trustedProxyCIDRs...)
if err != nil {
    log.Fatal(err)
}
```

Store the CIDR strings in your own config after fetching and filtering the provider list. Avoid embedding every published provider range unless every one of those ranges is a valid ingress path to your service.

Cloudflare-style configuration should trust `CF-Connecting-IP` only when the immediate peer is in Cloudflare's published CIDRs:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedProxies...),
    clientip.WithSources(clientip.HeaderSource("CF-Connecting-IP"), clientip.SourceRemoteAddr),
)
```

AWS ALB append mode typically uses `X-Forwarded-For`. Trust the narrowest ingress range that can reach your targets, such as explicit proxy addresses or ALB target subnets protected by security groups. Published AWS public service ranges are usually not the right trust boundary for private ALB-to-target traffic:

```go
resolver, err := clientip.New(
    clientip.WithTrustedProxies(trustedProxies...),
    clientip.WithSources(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
)
```

CloudFront and other CDN-origin configurations follow the same rule: a single-IP header is only trustworthy when the connecting peer is verified as that CDN. If the origin is reachable directly, a client can spoof headers such as `CF-Connecting-IP`, `True-Client-IP`, `Fastly-Client-IP`, or `X-Forwarded-For`; block direct origin access with firewall rules, security groups, or equivalent network policy.

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

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for local setup, test commands, documentation expectations, and pull request guidance.

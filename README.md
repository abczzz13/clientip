# clientip

[![CI](https://github.com/abczzz13/clientip/actions/workflows/ci.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abczzz13/clientip.svg)](https://pkg.go.dev/github.com/abczzz13/clientip)
[![License](https://img.shields.io/github/license/abczzz13/clientip)](LICENSE)

Secure client IP extraction for `net/http` and framework-agnostic request inputs with trusted proxy validation, configurable source priority, and optional logging/metrics.

## Stability

This project is pre-`v1.0.0` and still before `v0.1.0`, so public APIs may change as the package evolves.
Any breaking changes will be called out in `CHANGELOG.md`.

## Install

```bash
go get github.com/abczzz13/clientip
```

Optional Prometheus adapter:

```bash
go get github.com/abczzz13/clientip/prometheus
```

```go
import "github.com/abczzz13/clientip"
```

## Compatibility

- Core module (`github.com/abczzz13/clientip`) supports Go `1.21+`.
- Optional Prometheus adapter (`github.com/abczzz13/clientip/prometheus`) has a minimum Go version of `1.21`; CI currently validates consumer mode on Go `1.21.x` and `1.26.x`.
- Prometheus client dependency in the adapter is pinned to `github.com/prometheus/client_golang v1.21.1`.

## Quick start

By default, `New()` extracts from `RemoteAddr` only.

### Presets (recommended)

Use these when you want setup by deployment type instead of low-level options:

- `PresetDirectConnection()` app receives traffic directly (no trusted proxy headers)
- `PresetLoopbackReverseProxy()` reverse proxy on same host (`127.0.0.1` / `::1`)
- `PresetVMReverseProxy()` typical VM/private-network reverse proxy setup
- `PresetPreferredHeaderThenXFFLax("X-Frontend-IP")` prefer custom header, then `X-Forwarded-For`, then `RemoteAddr` (lax fallback)

#### Which preset should I use?

| If your setup looks like... | Start with... |
| --- | --- |
| App is directly internet-facing (no reverse proxy) | `PresetDirectConnection()` |
| NGINX/Caddy runs on the same host and proxies to your app | `PresetLoopbackReverseProxy()` |
| App runs on a VM/private network behind one or more internal proxies | `PresetVMReverseProxy()` |
| You have a best-effort custom header and want fallback to XFF | `PresetPreferredHeaderThenXFFLax("X-Frontend-IP")` |

Preset examples:

```go
// Typical VM setup (reverse proxy + private networking)
vmExtractor, err := clientip.New(
    clientip.PresetVMReverseProxy(),
)

// Prefer a best-effort header, then fallback to XFF and RemoteAddr
fallbackExtractor, err := clientip.New(
    clientip.TrustLoopbackProxy(),
    clientip.PresetPreferredHeaderThenXFFLax("X-Frontend-IP"),
)

_ = vmExtractor
_ = fallbackExtractor
```

### Simple (no proxy configuration)

```go
extractor, err := clientip.New()
if err != nil {
    log.Fatal(err)
}

ip, err := extractor.ExtractAddr(req)
if err != nil {
    fmt.Printf("Failed: %v\n", err)
    return
}

fmt.Printf("Client IP: %s\n", ip)
```

### Framework-friendly input API

Use `ExtractFrom` when your framework does not expose `*http.Request` directly.

```go
input := clientip.RequestInput{
    Context:    ctx,
    RemoteAddr: remoteAddr,
    Path:       path,
    Headers:    headersProvider, // any type implementing Values(name string) []string
}

extraction, err := extractor.ExtractFrom(input)
if err != nil {
    // handle error
}
```

`http.Header` already implements the required header interface, so for `net/http`
style frameworks (Gin, Echo, Chi) you can keep using `Extract(req)` directly.

`ExtractFrom` only requests header names required by the configured
`Priority(...)` sources.

```go
// Gin
extraction, err := extractor.Extract(c.Request)

// Echo
extraction, err := extractor.Extract(c.Request())
```

For `fasthttp`/Fiber style frameworks, provide a header adapter with
`HeaderValuesFunc` and preserve duplicate header lines:

```go
input := clientip.RequestInput{
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

Important: do not merge repeated header lines into a single comma-joined value.
Single-IP sources (for example `X-Real-IP` or custom headers) rely on per-line
values to detect duplicates in strict mode.

### Behind reverse proxies

```go
cidrs, err := clientip.ParseCIDRs("10.0.0.0/8", "172.16.0.0/12")
if err != nil {
    log.Fatal(err)
}

extractor, err := clientip.New(
    // min=0 allows requests where proxy headers contain only the client IP
    // (trusted RemoteAddr is validated separately).
    clientip.TrustProxyPrefixes(cidrs...),
    clientip.MinTrustedProxies(0),
    clientip.MaxTrustedProxies(3),
    clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
    clientip.WithChainSelection(clientip.RightmostUntrustedIP),
)
if err != nil {
    log.Fatal(err)
}
```

### Custom header priority

```go
extractor, err := clientip.New(
    clientip.TrustPrivateProxyRanges(),
    clientip.Priority(
        "CF-Connecting-IP",
        clientip.SourceXForwardedFor,
        clientip.SourceRemoteAddr,
    ),
)
```

### Security mode (strict vs lax)

```go
// Strict is default and fails closed on security errors
// (including malformed Forwarded and invalid present source values).
strictExtractor, _ := clientip.New(
    clientip.TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
    clientip.Priority("X-Frontend-IP", clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
    clientip.WithSecurityMode(clientip.SecurityModeStrict),
)

// Lax mode allows fallback to lower-priority sources after those errors.
laxExtractor, _ := clientip.New(
    clientip.TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
    clientip.Priority("X-Frontend-IP", clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
    clientip.WithSecurityMode(clientip.SecurityModeLax),
)
```

### Logging (bring your own)

By default, logging is disabled. Use `WithLogger` to opt in.

`WithLogger` accepts any implementation of:

```go
type Logger interface {
    WarnContext(context.Context, string, ...any)
}
```

This intentionally mirrors `slog.Logger.WarnContext`, so `*slog.Logger`
works directly with `WithLogger` (no adapter needed).

The context passed to logger calls comes from `req.Context()` (`Extract`) or
`RequestInput.Context` (`ExtractFrom`), so trace/span IDs added by middleware
remain available in logs.

Structured log attributes are passed as alternating key/value pairs, matching
the style used by `slog`.

When configured, the extractor emits warning logs for security-significant
conditions such as `multiple_headers`, `malformed_forwarded`, `chain_too_long`,
`untrusted_proxy`, `no_trusted_proxies`, `too_few_trusted_proxies`, and `too_many_trusted_proxies`.

```go
extractor, err := clientip.New(
    clientip.WithLogger(slog.Default()),
)
```

For loggers without context-aware APIs, adapters can simply ignore `ctx`:

```go
type stdLoggerAdapter struct{ l *log.Logger }

func (a stdLoggerAdapter) WarnContext(_ context.Context, msg string, args ...any) {
    a.l.Printf("WARN %s %v", msg, args)
}

extractor, err := clientip.New(
    clientip.WithLogger(stdLoggerAdapter{l: log.Default()}),
)
```

Tiny adapters for other popular loggers:

```go
type zapAdapter struct{ l *zap.SugaredLogger }

func (a zapAdapter) WarnContext(_ context.Context, msg string, args ...any) {
    a.l.With(args...).Warn(msg)
}
```

```go
type logrusAdapter struct{ l *logrus.Logger }

func (a logrusAdapter) WarnContext(_ context.Context, msg string, args ...any) {
    fields := logrus.Fields{}
    for i := 0; i+1 < len(args); i += 2 {
        key, ok := args[i].(string)
        if !ok {
            continue
        }
        fields[key] = args[i+1]
    }
    a.l.WithFields(fields).Warn(msg)
}
```

```go
type zerologAdapter struct{ l zerolog.Logger }

func (a zerologAdapter) WarnContext(_ context.Context, msg string, args ...any) {
    event := a.l.Warn()
    for i := 0; i+1 < len(args); i += 2 {
        key, ok := args[i].(string)
        if !ok {
            continue
        }
        event = event.Interface(key, args[i+1])
    }
    event.Msg(msg)
}
```

If your stack stores trace metadata in `context.Context`, enrich the adapter by
extracting that value and appending it to `args`.

### Prometheus metrics (simple setup)

```go
import clientipprom "github.com/abczzz13/clientip/prometheus"

extractor, err := clientip.New(
    clientipprom.WithMetrics(),
)
```

### Prometheus metrics (custom registerer)

```go
import (
    clientipprom "github.com/abczzz13/clientip/prometheus"
    "github.com/prometheus/client_golang/prometheus"
)

registry := prometheus.NewRegistry()

extractor, err := clientip.New(
    clientipprom.WithRegisterer(registry),
)
```

You can also construct metrics explicitly with `clientipprom.New()` or
`clientipprom.NewWithRegisterer(...)` and pass them via
`clientip.WithMetrics(...)`.

## Options

`New(opts...)` accepts one or more `Option` builders.

For one-shot extraction without reusing an extractor, use:

- `ExtractWithOptions(req, opts...)`
- `ExtractAddrWithOptions(req, opts...)`
- `ExtractFromWithOptions(input, opts...)`
- `ExtractAddrFromWithOptions(input, opts...)`

- `TrustProxyPrefixes(...netip.Prefix)` add trusted proxy network prefixes
- `TrustLoopbackProxy()` trust loopback upstream proxies (`127.0.0.0/8`, `::1/128`)
- `TrustPrivateProxyRanges()` trust private upstream proxy ranges (`10/8`, `172.16/12`, `192.168/16`, `fc00::/7`)
- `TrustLocalProxyDefaults()` trust loopback + private proxy ranges
- `TrustProxyAddrs(...netip.Addr)` add trusted upstream proxy host addresses
- `PresetDirectConnection()` remote-address only extraction preset
- `PresetLoopbackReverseProxy()` loopback reverse-proxy preset (`X-Forwarded-For`, then `RemoteAddr`)
- `PresetVMReverseProxy()` VM/private-network reverse-proxy preset (`X-Forwarded-For`, then `RemoteAddr`)
- `PresetPreferredHeaderThenXFFLax(string)` preferred-header fallback preset in lax mode
- `MinTrustedProxies(int)` / `MaxTrustedProxies(int)` set trusted-proxy count bounds for chain headers
- `AllowPrivateIPs(bool)` allow private client IPs
- `AllowReservedClientPrefixes(...netip.Prefix)` explicitly allow selected reserved/special-use client ranges
- `ParseCIDRs(...string)` parse CIDR strings to `[]netip.Prefix` for typed options
- `MaxChainLength(int)` limit proxy chain length from `Forwarded`/`X-Forwarded-For` (default 100)
- `WithChainSelection(ChainSelection)` choose `RightmostUntrustedIP` (default) or `LeftmostUntrustedIP`
- `Priority(...string)` set source order; built-ins: `SourceForwarded`, `SourceXForwardedFor`, `SourceXRealIP`, `SourceRemoteAddr` (built-in aliases are canonicalized, e.g. `"Forwarded"`, `"X-Forwarded-For"`, `"X_Real_IP"`, `"Remote-Addr"`), with at most one chain header source (`SourceForwarded` or `SourceXForwardedFor`) per extractor
- `WithSecurityMode(SecurityMode)` choose `SecurityModeStrict` (default) or `SecurityModeLax`
- `WithLogger(Logger)` inject logger implementation
- `WithMetrics(Metrics)` inject custom metrics implementation directly
- `WithMetricsFactory(func() (Metrics, error))` lazily construct metrics after option validation (last metrics option wins)
- `WithDebugInfo(bool)` include chain analysis in `Extraction.DebugInfo`

Default source order is `SourceRemoteAddr`.

Any header-based source requires trusted upstream proxy ranges (`TrustProxyPrefixes` or one of the trust helpers).

Prometheus adapter helpers from `github.com/abczzz13/clientip/prometheus`:

- `WithMetrics()` install Prometheus metrics on default registerer
- `WithRegisterer(prometheus.Registerer)` install Prometheus metrics on custom registerer
- `New()` / `NewWithRegisterer(prometheus.Registerer)` for explicit metrics construction

Proxy count bounds (`min`/`max`) apply to trusted proxies present in `Forwarded` (from `for=` values) and `X-Forwarded-For`.
The immediate proxy (`RemoteAddr`) is validated for trust separately before either header is trusted.

`AllowReservedClientPrefixes` only bypasses reserved/special-use filtering for matching ranges.
It does not bypass loopback/link-local/multicast/unspecified rejection, and private-IP policy remains controlled by `AllowPrivateIPs`.

## Extraction

```go
type Extraction struct {
    IP                netip.Addr
    Source            string // "forwarded", "x_forwarded_for", "x_real_ip", "remote_addr", or normalized custom header
    TrustedProxyCount int
    DebugInfo         *ChainDebugInfo
}

type HeaderValues interface {
    Values(name string) []string
}

type RequestInput struct {
    Context    context.Context
    RemoteAddr string
    Path       string
    Headers    HeaderValues
}

func (e *Extractor) Extract(req *http.Request, overrides ...OverrideOptions) (Extraction, error)
func (e *Extractor) ExtractAddr(req *http.Request, overrides ...OverrideOptions) (netip.Addr, error)
func (e *Extractor) ExtractFrom(input RequestInput, overrides ...OverrideOptions) (Extraction, error)
func (e *Extractor) ExtractAddrFrom(input RequestInput, overrides ...OverrideOptions) (netip.Addr, error)
```

When `Extract` returns a non-nil error, the returned `Extraction` value is
best-effort metadata only (typically `Source` when available). For chain
diagnostics, inspect typed errors like `ProxyValidationError` and
`InvalidIPError`.

Per-call overrides let you temporarily adjust policy for a single extraction:

```go
extraction, err := extractor.Extract(
    req,
    clientip.OverrideOptions{
        SecurityMode: clientip.Set(clientip.SecurityModeLax),
    },
)
```

Multiple `OverrideOptions` values are merged left-to-right; later set values
win. Only policy fields are overrideable (logger and metrics stay fixed per
extractor instance).

Custom header names are normalized via `NormalizeSourceName` (lowercase with underscores).

## Errors

```go
_, err := extractor.Extract(req)
if err != nil {
    switch {
    case errors.Is(err, clientip.ErrMultipleSingleIPHeaders):
        // Duplicate single-IP header values received
    case errors.Is(err, clientip.ErrInvalidForwardedHeader):
        // Malformed Forwarded header
    case errors.Is(err, clientip.ErrUntrustedProxy):
        // Forwarded/XFF came from an untrusted immediate proxy
    case errors.Is(err, clientip.ErrNoTrustedProxies):
        // No trusted proxies found in the chain
    case errors.Is(err, clientip.ErrTooFewTrustedProxies):
        // Trusted proxy count is below configured minimum
    case errors.Is(err, clientip.ErrTooManyTrustedProxies):
        // Trusted proxy count exceeds configured maximum
    case errors.Is(err, clientip.ErrInvalidIP):
        // Invalid or implausible client IP
    case errors.Is(err, clientip.ErrSourceUnavailable):
        // Requested source was not present on this request
    }

    var mh *clientip.MultipleHeadersError
    if errors.As(err, &mh) {
        // Inspect mh.HeaderName, mh.HeaderCount, or mh.RemoteAddr
    }
}
```

Typed chain-related errors expose additional context:

- `ProxyValidationError`: `Chain`, `TrustedProxyCount`, `MinTrustedProxies`, `MaxTrustedProxies`
- `InvalidIPError`: `Chain`, `ExtractedIP`, `Index`, `TrustedProxies`

## Security notes

- Parses RFC7239 `Forwarded` header (`for=` chain) and rejects malformed values
- Parses multiple `X-Forwarded-For` header lines as one chain (wire order preserved)
- Rejects multiple values for single-IP headers (for example repeated `X-Real-IP`)
- Requires the immediate proxy (`RemoteAddr`) to be trusted before honoring `Forwarded` or `X-Forwarded-For` (when trusted proxy prefixes are configured)
- Requires trusted proxy prefixes for any header-based source
- Allows at most one chain-header source (`Forwarded` or `X-Forwarded-For`) per extractor configuration
- Enforces trusted proxy count bounds and chain length
- Filters implausible IPs (loopback, multicast, reserved); optional private-IP and reserved-prefix allowlists
- Strict fail-closed behavior is the default (`SecurityModeStrict`) for security-significant errors and invalid present source values
- Set `WithSecurityMode(SecurityModeLax)` to continue fallback after security errors

## Security anti-patterns

- Do not include multiple competing header-based sources in `Priority(...)` for security decisions (for example custom header + chain header fallback). Prefer one canonical trusted header plus `SourceRemoteAddr` fallback only when required.
- Do not enable `SecurityModeLax` for security-enforcement decisions (ACLs, fraud/risk controls, authz). Use strict mode and fail closed.
- Do not trust broad proxy CIDRs unless they are truly under your control. Keep trusted ranges minimal and explicit.
- Do not treat a missing/invalid source as benign in critical paths; monitor and remediate extraction errors.

## Performance

- O(n) in chain length; extractor is safe for concurrent reuse

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

## Maintainer notes (multi-module)

- `prometheus/go.mod` intentionally does not use a local `replace` directive for `github.com/abczzz13/clientip`.
- For local co-development, create an uncommitted workspace with `go work init . ./prometheus`.
- Validate the adapter as a consumer with `GOWORK=off go -C prometheus test ./...`.
- `just` and CI validate the adapter in consumer mode by default (`GOWORK=off`); set `CLIENTIP_ADAPTER_GOWORK=auto` locally when you intentionally want workspace-mode adapter checks.
- Release in this order: tag root module `vX.Y.Z`, bump `prometheus/go.mod` to that version, then tag adapter module `prometheus/vX.Y.Z`.

## License

See `LICENSE`.

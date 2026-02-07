# clientip

[![CI](https://github.com/abczzz13/clientip/actions/workflows/ci.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abczzz13/clientip.svg)](https://pkg.go.dev/github.com/abczzz13/clientip)
[![License](https://img.shields.io/github/license/abczzz13/clientip)](LICENSE)

Secure client IP extraction for `net/http` requests with trusted proxy validation, configurable source priority, and optional logging/metrics.

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

## Quick start

### Simple (no proxy configuration)

```go
extractor, err := clientip.New()
if err != nil {
    log.Fatal(err)
}

result := extractor.ExtractIP(req)
if result.Valid() {
    fmt.Printf("Client IP: %s\n", result.IP)
} else {
    fmt.Printf("Failed: %v\n", result.Err)
}
```

### Behind reverse proxies

```go
cidrs, err := clientip.ParseCIDRs("10.0.0.0/8", "172.16.0.0/12")
if err != nil {
    log.Fatal(err)
}

extractor, err := clientip.New(
    // min=0 allows requests where XFF contains only the client IP
    // (trusted RemoteAddr is validated separately).
    clientip.TrustedProxies(cidrs, 0, 3),
    clientip.XFFStrategy(clientip.RightmostIP),
)
if err != nil {
    log.Fatal(err)
}
```

### Custom header priority

```go
extractor, err := clientip.New(
    clientip.Priority(
        "CF-Connecting-IP",
        clientip.SourceXForwardedFor,
        clientip.SourceRemoteAddr,
    ),
)
```

### Security mode (strict vs lax)

```go
// Strict is default and fails closed on security errors.
strictExtractor, _ := clientip.New(
    clientip.WithSecurityMode(clientip.SecurityModeStrict),
)

// Lax mode allows fallback to lower-priority sources.
laxExtractor, _ := clientip.New(
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

The context passed to logger calls comes from `req.Context()`, so trace/span IDs
added by middleware remain available in logs.

Structured log attributes are passed as alternating key/value pairs, matching
the style used by `slog`.

When configured, the extractor emits warning logs for security-significant
conditions such as `multiple_headers`, `chain_too_long`, `untrusted_proxy`,
`no_trusted_proxies`, `too_few_trusted_proxies`, and `too_many_trusted_proxies`.

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

## Options

- `TrustedProxies([]netip.Prefix, min, max)` set trusted proxy CIDRs with min/max trusted proxy counts in the XFF chain
- `TrustedCIDRs(...string)` parse CIDR strings in-place
- `MinProxies(int)` / `MaxProxies(int)` set bounds after `TrustedCIDRs`
- `AllowPrivateIPs(bool)` allow private client IPs
- `MaxChainLength(int)` limit `X-Forwarded-For` chain length (default 100)
- `XFFStrategy(Strategy)` choose `RightmostIP` (default) or `LeftmostIP`
- `Priority(...string)` set source order; built-ins: `SourceXForwardedFor`, `SourceXRealIP`, `SourceRemoteAddr`
- `WithSecurityMode(SecurityMode)` choose `SecurityModeStrict` (default) or `SecurityModeLax`
- `WithLogger(Logger)` inject logger implementation
- `WithMetrics(Metrics)` inject custom metrics implementation directly
- `WithDebugInfo(bool)` include chain analysis in `Result.DebugInfo`

Prometheus adapter options from `github.com/abczzz13/clientip/prometheus`:

- `WithMetrics()` enable Prometheus metrics with default registerer
- `WithRegisterer(prometheus.Registerer)` enable Prometheus metrics with custom registerer

Options are applied in order. If multiple metrics options are provided, the last one wins.

Proxy count bounds (`min`/`max`) apply only to trusted proxies present in `X-Forwarded-For`.
The immediate proxy (`RemoteAddr`) is validated for trust separately.

## Result

```go
type Result struct {
    IP                netip.Addr
    Source            string // "x_forwarded_for", "x_real_ip", "remote_addr", or normalized custom header
    Err               error
    TrustedProxyCount int
    DebugInfo         *ChainDebugInfo
}

func (r Result) Valid() bool
```

Custom header names are normalized via `NormalizeSourceName` (lowercase with underscores).

## Errors

```go
result := extractor.ExtractIP(req)
if !result.Valid() {
    switch {
    case errors.Is(result.Err, clientip.ErrMultipleXFFHeaders):
        // Possible spoofing attempt
    case errors.Is(result.Err, clientip.ErrUntrustedProxy):
        // XFF came from an untrusted immediate proxy
    case errors.Is(result.Err, clientip.ErrNoTrustedProxies):
        // No trusted proxies found in the chain
    case errors.Is(result.Err, clientip.ErrTooFewTrustedProxies):
        // Trusted proxy count is below configured minimum
    case errors.Is(result.Err, clientip.ErrTooManyTrustedProxies):
        // Trusted proxy count exceeds configured maximum
    case errors.Is(result.Err, clientip.ErrInvalidIP):
        // Invalid or implausible client IP
    }

    var mh *clientip.MultipleHeadersError
    if errors.As(result.Err, &mh) {
        // Inspect mh.HeaderCount or mh.RemoteAddr
    }
}
```

## Security notes

- Rejects multiple `X-Forwarded-For` headers (spoofing defense)
- Requires the immediate proxy (`RemoteAddr`) to be trusted before honoring `X-Forwarded-For` (when trusted CIDRs are configured)
- Enforces trusted proxy count bounds and chain length
- Filters implausible IPs (loopback, multicast, reserved); optional private IP allowlist
- Strict fail-closed behavior is the default (`SecurityModeStrict`)
- Set `WithSecurityMode(SecurityModeLax)` to continue fallback after security errors

## Performance

- O(n) in chain length; extractor is safe for concurrent reuse

## Maintainer notes (multi-module)

- `prometheus/go.mod` intentionally does not use a local `replace` directive for `github.com/abczzz13/clientip`.
- For local co-development, create an uncommitted workspace with `go work init . ./prometheus`.
- Validate the adapter as a consumer with `GOWORK=off go -C prometheus test ./...`.
- `just` uses consumer mode for adapter checks by default; override locally with `CLIENTIP_ADAPTER_GOWORK=auto just <target>`.
- Release in this order: tag root module `vX.Y.Z`, bump `prometheus/go.mod` to that version, then tag adapter module `prometheus/vX.Y.Z`.

## License

See `LICENSE`.

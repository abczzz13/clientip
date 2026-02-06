# clientip

[![CI](https://github.com/abczzz13/clientip/actions/workflows/ci.yml/badge.svg)](https://github.com/abczzz13/clientip/actions/workflows/ci.yml)
[![Go Reference](https://pkg.go.dev/badge/github.com/abczzz13/clientip.svg)](https://pkg.go.dev/github.com/abczzz13/clientip)
[![License](https://img.shields.io/github/license/abczzz13/clientip)](LICENSE)

Secure client IP extraction for `net/http` requests with trusted proxy validation, configurable source priority, and optional logging/metrics.

## Install

```bash
go get github.com/abczzz13/clientip
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
    clientip.TrustedProxies(cidrs, 1, 3),
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

### Prometheus metrics (simple setup)

```go
extractor, err := clientip.New(
    clientip.WithPrometheusMetrics(),
)
```

### Prometheus metrics (custom registerer)

```go
registry := prometheus.NewRegistry()

extractor, err := clientip.New(
    clientip.WithPrometheusMetricsRegisterer(registry),
)
```

## Options

- `TrustedProxies([]netip.Prefix, min, max)` set trusted proxy CIDRs with min/max proxy counts
- `TrustedCIDRs(...string)` parse CIDR strings in-place
- `MinProxies(int)` / `MaxProxies(int)` set bounds after `TrustedCIDRs`
- `AllowPrivateIPs(bool)` allow private client IPs
- `MaxChainLength(int)` limit `X-Forwarded-For` chain length (default 100)
- `XFFStrategy(Strategy)` choose `RightmostIP` (default) or `LeftmostIP`
- `Priority(...string)` set source order; built-ins: `SourceXForwardedFor`, `SourceXRealIP`, `SourceRemoteAddr`
- `WithSecurityMode(SecurityMode)` choose `SecurityModeStrict` (default) or `SecurityModeLax`
- `WithLogger(*slog.Logger)` inject logger
- `WithPrometheusMetrics()` enable Prometheus metrics with default registerer
- `WithPrometheusMetricsRegisterer(prometheus.Registerer)` enable Prometheus metrics with custom registerer
- `WithMetrics(Metrics)` inject custom metrics implementation directly
- `WithDebugInfo(bool)` include chain analysis in `Result.DebugInfo`

Options are applied in order. If multiple metrics options are provided, the last one wins.

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
    case errors.Is(result.Err, clientip.ErrProxyCountOutOfRange):
        // Proxy count outside bounds
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
- Enforces proxy count bounds and chain length
- Filters implausible IPs (loopback, multicast, reserved); optional private IP allowlist
- Strict fail-closed behavior is the default (`SecurityModeStrict`)
- Set `WithSecurityMode(SecurityModeLax)` to continue fallback after security errors

## Performance

- O(n) in chain length; extractor is safe for concurrent reuse

## License

See `LICENSE`.

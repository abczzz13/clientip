# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

## [0.0.4] - 2026-02-13

### Added

- First-class RFC7239 `Forwarded` header support (`for=` chain parsing) with built-in source constant `SourceForwarded`.
- New malformed-header error sentinel: `ErrInvalidForwardedHeader`.
- New source-absence sentinel: `ErrSourceUnavailable`.
- New duplicate single-IP header error sentinel: `ErrMultipleSingleIPHeaders`.
- Trust helper options for common deployments: `TrustLoopbackProxy()`, `TrustPrivateProxyRanges()`, `TrustLocalProxyDefaults()`, and `TrustProxyIP(string)`.
- New deployment presets: `PresetDirectConnection()`, `PresetLoopbackReverseProxy()`, `PresetVMReverseProxy()`, and `PresetPreferredHeaderThenXFFLax(string)`.
- New extraction API: `Extract(req, overrides...)` and `ExtractAddr(req, overrides...)` returning `(value, error)`.
- One-shot convenience helpers: `ExtractWithOptions(req, opts)` and `ExtractAddrWithOptions(req, opts)`.
- Per-call policy override support via `OverrideOptions` and `Set(...)`.

### Changed

- Default source priority is now `RemoteAddr` only (safe-by-default, no implicit header trust).
- Header-based sources now require trusted upstream proxy CIDRs (`TrustedCIDRs`, `TrustedProxies`, or trust helpers).
- `Priority(...)` now allows at most one chain-header source per extractor (`SourceForwarded` or `SourceXForwardedFor`).
- Proxy-chain extraction, trust validation, and chain limits now apply consistently to `Forwarded` and `X-Forwarded-For`.
- In `SecurityModeStrict` (default), malformed `Forwarded` and invalid present source values are terminal (fail closed); `SecurityModeLax` allows fallback.
- Chain selection naming is now explicit: `WithChainSelection(ChainSelection)` with `RightmostUntrustedIP` (default) and `LeftmostUntrustedIP`.
- Single-IP header sources now explicitly reject multiple header values and fail closed in strict mode.
- `parseIP` now trims wrapping quotes/brackets only when delimiters are matched.
- `ProxyValidationError` and `InvalidIPError` now expose `Chain` instead of `XFF`.
- `Priority(...)` now canonicalizes built-in source aliases (for example `"Forwarded"`, `"X-Forwarded-For"`, `"X_Real_IP"`, `"Remote-Addr"`).
- Reserved/special-use client IP filtering now covers additional RFC ranges (for example benchmarking, NAT64, ORCHIDv2, and future-use ranges).
- Prometheus adapter supports both options fragments (`WithMetrics()`, `WithRegisterer(...)`) and explicit constructors (`New()`, `NewWithRegisterer(...)`).
- Result handling is now centered around `Extraction` + error return values.
- `New` now accepts option builders directly (`New(opts...)`) and no longer requires `OptionsFrom(...)` for composition.
- `WithMetricsFactory(...)` now executes only after option validation and only for the final winning metrics option.
- No-op per-call overrides now avoid unnecessary config cloning and source-chain rebuilding.
- `Option` is now opaque (custom `func(*Config) error` option builders are no longer part of the public API).
- `ChainSelection.Valid()`, `SecurityMode.Valid()`, `SetValue.IsSet()`, and `SetValue.Value()` are now internal helpers.
- Prometheus adapter constructors now return `clientip.Metrics` (the concrete metrics type is no longer exported).
- `just` and CI now validate the Prometheus adapter in consumer mode by default (`GOWORK=off`), with workspace-mode checks opt-in via `CLIENTIP_ADAPTER_GOWORK=auto`.

## [0.0.3] - 2026-02-07

### Changed

- Logging now uses a bring-your-own `Logger` interface (`WithLogger(Logger)`) instead of a concrete `*slog.Logger` type.
- Default logging remains disabled via a no-op logger; users can opt in with `WithLogger(...)`.
- Proxy validation errors are now explicit and specific: `ErrUntrustedProxy`, `ErrNoTrustedProxies`, `ErrTooFewTrustedProxies`, and `ErrTooManyTrustedProxies`.
- When trusted CIDRs are configured, `X-Forwarded-For` is only honored if the immediate proxy (`RemoteAddr`) is trusted.
- `ErrNoTrustedProxies` is now emitted only when `minTrustedProxies > 0`; with `minTrustedProxies == 0`, client-only `X-Forwarded-For` chains are allowed.

### Added

- Additional security warning logs for `chain_too_long`, `untrusted_proxy`, `no_trusted_proxies`, `too_few_trusted_proxies`, and `too_many_trusted_proxies` events.

## [0.0.2] - 2026-02-07

### Changed

- Prometheus integration moved out of the root module into an optional adapter module: `github.com/abczzz13/clientip/prometheus`.
- Root package now exposes only generic metrics wiring (`WithMetrics(Metrics)`), while Prometheus-specific APIs live only in the adapter module.
- Adapter API is intentionally minimal: `prometheus.WithMetrics()`, `prometheus.WithRegisterer(prometheus.Registerer)`, `prometheus.New()`, and `prometheus.NewWithRegisterer(...)`.
- Adapter module now validates against published root-module versions (no committed local `replace`), and adapter checks default to `GOWORK=off` (overridable locally via `CLIENTIP_ADAPTER_GOWORK`).

## [0.0.1] - 2026-02-06

### Added

- Initial public release of `clientip`.
- Secure client IP extraction for `net/http` from prioritized sources (`X-Forwarded-For`, `X-Real-IP`, `RemoteAddr`, and custom headers).
- Trusted proxy CIDR validation with configurable minimum and maximum proxy counts.
- XFF strategies (`RightmostIP`, `LeftmostIP`) and configurable maximum chain length.
- Strict-by-default security mode (`SecurityModeStrict`) with optional lax mode (`SecurityModeLax`).
- Result metadata including extraction source, trusted proxy count, and optional chain debug info.
- Pluggable observability via logger and metrics interfaces.
- Prometheus integration options:
  - `WithPrometheusMetrics()`
  - `WithPrometheusMetricsRegisterer(prometheus.Registerer)`

### Security

- Fail-closed default behavior for security-significant extraction errors.
- Multiple `X-Forwarded-For` headers are treated as spoofing signals.
- Rejection of invalid and implausible client IPs (for example loopback and multicast by default).

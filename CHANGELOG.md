# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

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

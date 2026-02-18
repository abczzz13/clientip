# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

## [Unreleased]

## [0.0.6] - 2026-02-18

### Added

- Framework-agnostic extraction API: `RequestInput`, `HeaderValues`, `HeaderValuesFunc`, `Extractor.ExtractFrom`, and `Extractor.ExtractAddrFrom`.
- One-shot helpers for framework-agnostic input: `ExtractFromWithOptions` and `ExtractAddrFromWithOptions`.
- New examples and tests covering framework-style integrations, parity with `net/http` extraction behavior, context/path propagation for logging, and cancellation behavior for framework header providers.
- Additional `Forwarded` parser tests for quoted delimiters/escapes and malformed quoted-value edge cases.
- Benchmark coverage for `ExtractFrom` with both `http.Header` and `HeaderValuesFunc` header providers, plus parameter-rich `Forwarded` header extraction.
- New option `AllowReservedClientPrefixes(...netip.Prefix)` to explicitly allow selected reserved/special-use client ranges.

### Changed

- Internal extraction now keeps `*http.Request` as the core representation; `ExtractFrom` adapts `RequestInput` into a minimal request while preserving existing security behavior for duplicate single-IP headers and trusted-proxy validation.
- `ExtractFrom` now avoids header adaptation work for remote-address-only priority, lazily materializes header maps for custom header providers, and checks `RequestInput.Context` cancellation before consulting header providers.
- Header-based source extraction now uses canonicalized precomputed header keys with direct map lookups (`http.Header[key]`) on hot paths.
- `Forwarded` parsing now uses a single-pass segment scanner that respects quoted delimiters and escape sequences while preserving strict malformed-header validation.
- `X-Forwarded-For` extraction now combines multiple header lines into one logical chain (matching `Forwarded`) instead of treating duplicates as a terminal error, and no longer emits the `multiple_headers` security event for this case.
- Removed `ErrMultipleXFFHeaders`; duplicate-line handling for `X-Forwarded-For` is no longer an error condition.
- Option APIs are now typed-first: trusted proxy configuration now uses `TrustProxyPrefixes`, `TrustProxyAddrs`, `MinTrustedProxies`, and `MaxTrustedProxies`; reserved-range allowlisting now uses `AllowReservedClientPrefixes`; and per-call overrides use `TrustedProxyPrefixes` and `AllowReservedClientPrefixes` fields. This replaces `TrustedProxies`, `TrustedCIDRs`, `TrustProxyIP`, `MinProxies`, `MaxProxies`, and `AllowReservedClientCIDRs`.

## [0.0.5] - 2026-02-14

### Added

- A precomputed trusted-proxy CIDR matcher (binary prefix trie) with dedicated tests and large-CIDR benchmark coverage.
- New benchmark coverage for `Forwarded` extraction, preferred-source fallback behavior, and trusted-proxy lookup performance at large CIDR scales.
- New `just` benchmark workflow commands: `bench`, `bench-all`, `bench-save`, `bench-compare-saved`, and `bench-compare`.

### Changed

- Trusted proxy matching now uses the precomputed matcher during extraction, with linear CIDR fallback retained for manually constructed configs.
- Per-call overrides now preserve the existing trusted-proxy matcher when CIDRs are unchanged and rebuild it only when `TrustedProxyCIDRs` is overridden.
- Header-chain extraction now defers untrusted-chain string construction until needed, reducing avoidable allocations on the hot path.
- Source-unavailable error values are now reused per source extractor instead of being reallocated on each request.
- `RemoteAddr` handling now uses dedicated parsing that prefers host extraction, improving behavior for host:port inputs (including non-numeric port suffixes) and reducing false parses.
- Internal chain analysis now carries the selected client IP through analysis to avoid reparsing and reduce duplicate work.
- Root module minimum Go version is now `1.21` (down from `1.24`) with `X-Forwarded-For` parsing and integer range loops rewritten to Go 1.21-compatible forms.
- Prometheus adapter now pins `github.com/prometheus/client_golang` to `v1.21.1`.
- CI now tests the root module on a Go `1.21.x` + `1.26.x` matrix, keeps adapter consumer-mode checks on Go `1.26.x` until a Go `1.21` root tag is available, and runs lint/security tooling on Go `1.26.x` to satisfy pinned tool requirements.

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

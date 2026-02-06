# Changelog

All notable changes to this project will be documented in this file.

The format is based on Keep a Changelog and this project follows Semantic Versioning.

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

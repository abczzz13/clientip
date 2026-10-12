# Security Policy

## Supported Versions

Security fixes target the `main` branch and the latest published release of
each current module:

- `github.com/abczzz13/clientip`
- `github.com/abczzz13/clientip/observe/prometheus`

Older releases and the legacy `github.com/abczzz13/clientip/prometheus` module
are not maintained for security fixes unless a maintainer announces otherwise.
Use the latest release of the module you depend on.

## Go Toolchain Security

The minimum Go version in `go.mod` describes source compatibility, not security
support. Build and deploy applications with a patched, supported Go toolchain.
For Go 1.26, use at least 1.26.9, which fixes the `net/http` vulnerabilities
reported in the October 2026 security scan. Updating this library alone does not
update the standard library linked into your application; rebuild and redeploy
with the patched toolchain.

CI selects the latest patch of its configured Go release lines using
`actions/setup-go` with `check-latest: true` to avoid stale runner toolchains.

## Scope

Please report issues that could affect the safety or reliability of client IP
resolution, including:

- Spoofable client IP selection when trusted proxies are configured correctly.
- Parser behavior that accepts malformed `Forwarded` or `X-Forwarded-For` input in a security-sensitive path.
- Incorrect fallback behavior that could turn a strict failure into a trusted result.
- Denial-of-service behavior in header parsing or trust-chain validation.
- Sensitive data exposure through logging, metrics, or error values.
- Vulnerabilities in direct or adapter dependencies.

## Reporting a Vulnerability

If you believe you have found a security vulnerability, please report it using
GitHub's private vulnerability reporting:
https://github.com/abczzz13/clientip/security/advisories/new

Please include the affected module path and version, Go toolchain version,
resolver options, proxy topology, relevant `RemoteAddr` and header values,
expected result, actual result, and whether operational fallback was enabled.
Avoid publishing exploit details publicly before triage.

## Response Timeline

We aim to acknowledge reports within 5 business days and provide a status
update within 10 business days.

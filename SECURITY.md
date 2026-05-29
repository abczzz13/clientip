# Security Policy

## Supported Versions

This project is pre-`v0.1.0`. Security fixes are expected to target the latest
published version and the `main` branch unless a maintainer announces otherwise.

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

Please include the resolver options, proxy topology, relevant `RemoteAddr` and
header values, expected result, actual result, and whether operational fallback
was enabled. Avoid publishing exploit details publicly before triage.

## Response Timeline

We aim to acknowledge reports within 5 business days and provide a status
update within 10 business days.

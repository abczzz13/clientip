# Threat Model

This document describes what `clientip` is designed to protect, what it assumes, and what it deliberately does not try to solve.

## Security Goals

`clientip` helps applications choose a client IP address for decisions such as:

- rate limiting and abuse controls
- ACLs and authorization policy
- audit trails and incident investigation
- security-sensitive logging and metrics labels

The primary goal is to avoid trusting spoofable forwarding headers unless the request came through a proxy that the application explicitly trusts.

## Trust Boundary

`RemoteAddr` is the only source that comes from the direct network peer observed by the HTTP server. Forwarding headers such as `Forwarded`, `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, and vendor-specific headers are plain HTTP headers. A client can spoof them unless an upstream proxy removes or rewrites untrusted values before forwarding the request.

For header-based sources, the application must configure `WithTrustedProxies` with the narrowest CIDR ranges that can actually connect to the service. These are usually load-balancer, reverse-proxy, CDN edge, or private ingress ranges, not broad cloud-provider address feeds.

## Assumptions

`clientip` assumes that:

- configured trusted proxies are controlled by the operator or provider and enforce the expected header behavior
- direct origin access is blocked when a CDN or edge proxy is supposed to be the only ingress path
- the application keeps trusted proxy CIDRs current through its own deployment or configuration process
- framework integrations preserve repeated header-line values in order
- the caller treats `Resolve` results differently from operational fallback results

## Non-Goals

`clientip` does not:

- make arbitrary forwarding headers trustworthy without CIDR-validated trusted proxies
- fetch or refresh provider IP ranges automatically
- implement count-only proxy trust
- authenticate proxies cryptographically
- decide application response status codes or rejection bodies
- anonymize or redact IP addresses in caller logs, metrics, or storage

## Failure Behavior

Strict resolution fails closed. Source absence can allow the next configured source to run, but malformed headers, invalid IPs, proxy-trust failures, chain-limit failures, context cancellation, and unexpected extractor errors are terminal.

Operational fallback is intentionally separate. `ResolveOperational` can return a best-effort value for analytics or logging, but fallback results should not be used for authorization, ACLs, rate-limit identity, or other trust-boundary decisions.

## Privacy Notes

IP addresses can be personal data. Avoid logging full addresses unless needed, define retention periods, and consider redaction or aggregation for analytics. `clientip` exposes logging and observation hooks, but privacy policy and storage behavior are application responsibilities.

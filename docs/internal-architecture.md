# Internal Architecture

This document is for contributors reading or changing the implementation. Public API usage belongs in `README.md` and package godocs.

## Resolution Flow

`Resolver` is the public entrypoint. It delegates strict extraction to an internal `extractor`, wraps the result in `Result`, applies operational fallback when requested, and notifies any configured `Observer` once per resolver call.

The internal flow is:

1. `Resolver.Resolve*` receives `*http.Request`, `Input`, or plain headers.
2. `requestView` adapts the input shape while preserving repeated header-line values.
3. `extractor` walks configured sources in order.
4. Source-specific extractors return either an `Extraction`, an `extractionFailure`, or a parser error.
5. `source_execution.go` adapts low-level failures into public typed errors and security log events.

## Source Model

`SourceRemoteAddr` reads the connecting peer and is the only inherently trusted source.

Chain header sources, such as `Forwarded` and `X-Forwarded-For`, parse a list of hops. The immediate `RemoteAddr` peer must be trusted before any header value is considered. The default selection is the rightmost untrusted hop before the trusted suffix. If every parsed hop is trusted, the oldest hop is selected and still validated by the client-IP policy.

Single-IP header sources, such as `X-Real-IP` or `CF-Connecting-IP`, are trusted only when the immediate peer is in `WithTrustedProxies`. Duplicate single-IP header lines are terminal because attribution is ambiguous and spoof-prone.

`SourceStaticFallback` is result-only. It is never a configured extraction source.

## Request Adapter

`requestView` keeps source extractors independent from `*http.Request` and `Input`. Header providers must preserve repeated header lines as separate values because duplicate single-IP headers must be detected and chain headers need stable order across repeated lines.

## Trust Model

Trusted proxy configuration is CIDR based. `WithMinTrustedProxies` and `WithMaxTrustedProxies` validate how many CIDR-trusted hops were observed; they do not implement count-only trust and do not make a header source trustworthy by themselves.

The prefix matcher uses a binary trie for hot-path CIDR lookup. A linear CIDR fallback remains for uninitialized or manually constructed policy state.

## Error Model

Low-level source extractors do not construct public errors directly. They return `extractionFailure` values for policy failures and direct parser errors for syntax/length failures.

`source_execution.go` is the boundary that converts those internal failures into exported sentinel and typed errors. It also emits security logs. This keeps the low-level extractors small and keeps the public error surface centralized.

`ErrSourceUnavailable` is the only normal non-terminal source failure. Malformed headers, untrusted proxies, chain limits, invalid client IPs, and context cancellation are terminal.

## Observability

`Logger` records security-significant extractor events with request context. `Observer` records the final resolver result, including strict failures and successful operational fallbacks.

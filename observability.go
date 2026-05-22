package clientip

import "context"

// SecurityEvent... constants are stable public labels for extractor security
// events. Log consumers can depend on these names.
const (
	SecurityEventMultipleHeaders       = "multiple_headers"
	SecurityEventChainTooLong          = "chain_too_long"
	SecurityEventUntrustedProxy        = "untrusted_proxy"
	SecurityEventNoTrustedProxies      = "no_trusted_proxies"
	SecurityEventTooFewTrustedProxies  = "too_few_trusted_proxies"
	SecurityEventTooManyTrustedProxies = "too_many_trusted_proxies"
	SecurityEventInvalidIP             = "invalid_ip"
	SecurityEventReservedIP            = "reserved_ip"
	SecurityEventPrivateIP             = "private_ip"
	SecurityEventMalformedForwarded    = "malformed_forwarded"
)

// Logger records security-significant events emitted by extractor.
//
// Implementations should be safe for concurrent use, as a single extractor
// instance is typically shared across many goroutines.
//
// The provided context comes from the inbound HTTP request and can carry
// tracing metadata (for example, trace or span IDs).
//
// Operational fallback does not emit separate log events. Inspect
// Result.FallbackUsed when that distinction matters.
//
// The interface intentionally mirrors slog's WarnContext signature, so
// *slog.Logger can be used directly without an adapter.
type Logger interface {
	WarnContext(ctx context.Context, msg string, args ...any)
}

// noopLogger is the default Logger implementation when logging is not
// explicitly configured.
type noopLogger struct{}

func (noopLogger) WarnContext(context.Context, string, ...any) {}

// Observer receives one event per resolver call on a valid Resolver.
//
// Implementations should be safe for concurrent use. Observer is result-level,
// so it can see strict successes, strict failures, and operational fallbacks.
type Observer interface {
	OnResolved(ctx context.Context, result Result)
}

type noopObserver struct{}

func (noopObserver) OnResolved(context.Context, Result) {}

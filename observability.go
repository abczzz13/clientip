package clientip

import "context"

// SecurityEvent... constants are stable public labels for extractor security
// events. Metrics adapters and log consumers can depend on these names.
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

// Logger records security-significant events emitted by Extractor.
//
// Implementations should be safe for concurrent use, as a single Extractor
// instance is typically shared across many goroutines.
//
// The provided context comes from the inbound HTTP request and can carry
// tracing metadata (for example, trace or span IDs).
//
// Resolver preferred fallback does not emit separate log events in this phase.
// Inspect Resolution.FallbackUsed when that distinction matters.
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

// Metrics records extraction outcomes and security events emitted by
// Extractor.
//
// Implementations should be safe for concurrent use, as a single Extractor
// instance is typically shared across many goroutines.
//
// Security event labels are the exported SecurityEvent... constants.
// Resolver preferred fallback does not emit separate metrics in this phase;
// inspect Resolution.FallbackUsed when that distinction matters.
type Metrics interface {
	// RecordExtractionSuccess is called when a source successfully returns a
	// client IP.
	RecordExtractionSuccess(source string)
	// RecordExtractionFailure is called when a source is attempted but cannot
	// return a valid client IP.
	RecordExtractionFailure(source string)
	// RecordSecurityEvent is called when the extractor observes a
	// security-relevant condition.
	RecordSecurityEvent(event string)
}

// noopMetrics is the default Metrics implementation when metrics are not
// explicitly configured.
type noopMetrics struct{}

func (noopMetrics) RecordExtractionSuccess(string) {}

func (noopMetrics) RecordExtractionFailure(string) {}

func (noopMetrics) RecordSecurityEvent(string) {}

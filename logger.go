package clientip

import (
	"context"
)

// Logger records security-significant events emitted by Extractor.
//
// Implementations should be safe for concurrent use, as a single Extractor
// instance is typically shared across many goroutines.
//
// The provided context comes from the inbound HTTP request and can carry
// tracing metadata (for example, trace or span IDs).
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

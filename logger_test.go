package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"sync"
	"testing"
)

type loggerTestContextKey string

type capturedLogEntry struct {
	ctx   context.Context
	attrs map[string]any
}

type capturedLogger struct {
	mu      sync.Mutex
	entries []capturedLogEntry
}

func (l *capturedLogger) WarnContext(ctx context.Context, msg string, args ...any) {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = append(l.entries, capturedLogEntry{
		ctx:   ctx,
		attrs: attrsToMap(args),
	})
}

func (l *capturedLogger) snapshot() []capturedLogEntry {
	l.mu.Lock()
	defer l.mu.Unlock()

	entries := make([]capturedLogEntry, len(l.entries))
	copy(entries, l.entries)
	return entries
}

func attrsToMap(args []any) map[string]any {
	attrs := make(map[string]any)
	for i := 0; i+1 < len(args); i += 2 {
		key, ok := args[i].(string)
		if !ok {
			continue
		}
		attrs[key] = args[i+1]
	}
	return attrs
}

func assertAttr(t *testing.T, attrs map[string]any, key string, want any) {
	t.Helper()

	got, ok := attrs[key]
	if !ok {
		t.Fatalf("missing %q attr", key)
	}

	if got != want {
		t.Fatalf("%s attr = %v, want %v", key, got, want)
	}
}

func assertCommonSecurityWarningAttrs(t *testing.T, attrs map[string]any, event, source, path, remoteAddr string) {
	t.Helper()

	assertAttr(t, attrs, "event", event)
	assertAttr(t, attrs, "source", source)
	assertAttr(t, attrs, "path", path)
	assertAttr(t, attrs, "remote_addr", remoteAddr)
}

func TestLogging_MultipleHeaders_WarnsWithRequestContext(t *testing.T) {
	logger := &capturedLogger{}

	extractor, err := New(
		WithLogger(logger),
		TrustProxyIP("1.1.1.1"),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.WithValue(context.Background(), loggerTestContextKey("trace_id"), "trace-123")
	req := (&http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/multiple-headers"},
	}).WithContext(ctx)
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "9.9.9.9")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail for multiple X-Forwarded-For headers")
	}
	if !errors.Is(result.Err, ErrMultipleXFFHeaders) {
		t.Fatalf("error = %v, want ErrMultipleXFFHeaders", result.Err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	if got := entry.ctx.Value(loggerTestContextKey("trace_id")); got != "trace-123" {
		t.Fatalf("trace context value = %v, want %q", got, "trace-123")
	}

	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventMultipleHeaders,
		SourceXForwardedFor,
		"/test/multiple-headers",
		"1.1.1.1:8080",
	)
	assertAttr(t, entry.attrs, "header_count", 2)
}

func TestLogging_ChainTooLong_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}

	extractor, err := New(
		WithLogger(logger),
		TrustProxyIP("1.1.1.1"),
		Priority(SourceXForwardedFor),
		MaxChainLength(2),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/chain-too-long"},
	}
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9, 4.4.4.4")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail for overlong X-Forwarded-For chain")
	}
	if !errors.Is(result.Err, ErrChainTooLong) {
		t.Fatalf("error = %v, want ErrChainTooLong", result.Err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventChainTooLong,
		SourceXForwardedFor,
		"/test/chain-too-long",
		"1.1.1.1:8080",
	)
	assertAttr(t, entry.attrs, "chain_length", 3)
	assertAttr(t, entry.attrs, "max_length", 2)
}

func TestLogging_TooFewTrustedProxies_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithLogger(logger),
		TrustedProxies(cidrs, 2, 3),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/proxy-count"},
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail for too few trusted proxies")
	}
	if !errors.Is(result.Err, ErrTooFewTrustedProxies) {
		t.Fatalf("error = %v, want ErrTooFewTrustedProxies", result.Err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventTooFewTrustedProxies,
		SourceXForwardedFor,
		"/test/proxy-count",
		"10.0.0.1:8080",
	)
	assertAttr(t, entry.attrs, "trusted_proxy_count", 1)
	assertAttr(t, entry.attrs, "min_trusted_proxies", 2)
	assertAttr(t, entry.attrs, "max_trusted_proxies", 3)
}

func TestLogging_NoTrustedProxies_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithLogger(logger),
		TrustedProxies(cidrs, 1, 3),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/no-trusted-proxies"},
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail when no trusted proxies are present in XFF")
	}
	if !errors.Is(result.Err, ErrNoTrustedProxies) {
		t.Fatalf("error = %v, want ErrNoTrustedProxies", result.Err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventNoTrustedProxies,
		SourceXForwardedFor,
		"/test/no-trusted-proxies",
		"10.0.0.1:8080",
	)
	assertAttr(t, entry.attrs, "trusted_proxy_count", 0)
	assertAttr(t, entry.attrs, "min_trusted_proxies", 1)
	assertAttr(t, entry.attrs, "max_trusted_proxies", 3)
}

func TestLogging_TooManyTrustedProxies_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithLogger(logger),
		TrustedProxies(cidrs, 1, 1),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.2:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/too-many-proxies"},
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1, 10.0.0.2")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail for too many trusted proxies")
	}
	if !errors.Is(result.Err, ErrTooManyTrustedProxies) {
		t.Fatalf("error = %v, want ErrTooManyTrustedProxies", result.Err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventTooManyTrustedProxies,
		SourceXForwardedFor,
		"/test/too-many-proxies",
		"10.0.0.2:8080",
	)
	assertAttr(t, entry.attrs, "trusted_proxy_count", 2)
	assertAttr(t, entry.attrs, "min_trusted_proxies", 1)
	assertAttr(t, entry.attrs, "max_trusted_proxies", 1)
}

func TestLogging_UntrustedProxy_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithLogger(logger),
		TrustedProxies(cidrs, 1, 3),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/untrusted-proxy"},
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail for untrusted proxy")
	}
	if !errors.Is(result.Err, ErrUntrustedProxy) {
		t.Fatalf("error = %v, want ErrUntrustedProxy", result.Err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventUntrustedProxy,
		SourceXForwardedFor,
		"/test/untrusted-proxy",
		"8.8.8.8:8080",
	)
}

func TestLogging_MalformedForwarded_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}

	extractor, err := New(
		WithLogger(logger),
		TrustProxyIP("1.1.1.1"),
		Priority(SourceForwarded, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
		URL:        &url.URL{Path: "/test/malformed-forwarded"},
	}
	req.Header.Set("Forwarded", "for=\"1.1.1.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail closed on malformed Forwarded")
	}
	if !errors.Is(result.Err, ErrInvalidForwardedHeader) {
		t.Fatalf("error = %v, want ErrInvalidForwardedHeader", result.Err)
	}
	if result.Source != SourceForwarded {
		t.Fatalf("source = %q, want %q", result.Source, SourceForwarded)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventMalformedForwarded,
		SourceForwarded,
		"/test/malformed-forwarded",
		"1.1.1.1:8080",
	)
}

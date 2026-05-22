package clientip

import (
	"context"
	"errors"
	"net/netip"
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

func (l *capturedLogger) clear() {
	l.mu.Lock()
	defer l.mu.Unlock()

	l.entries = nil
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

func assertCommonSecurityWarningAttrs(t *testing.T, attrs map[string]any, event string, source Source, path, remoteAddr string) {
	t.Helper()

	assertAttr(t, attrs, "event", event)
	assertAttr(t, attrs, "source", source.String())
	assertAttr(t, attrs, "path", path)
	assertAttr(t, attrs, "remote_addr", remoteAddr)
}

func TestLogging_MultipleXFFHeaders_DoNotWarn(t *testing.T) {
	logger := &capturedLogger{}

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = mustProxyPrefixesFromAddrs(t, netip.MustParseAddr("1.1.1.1"))
	cfg.Sources = []Source{SourceXForwardedFor}
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("1.1.1.1:8080", "/test/multiple-headers")
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "9.9.9.9")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected extraction success, got error: %v", err)
	}
	if got, want := result.Source, SourceXForwardedFor; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
	if got, want := result.IP.String(), "9.9.9.9"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}

	entries := logger.snapshot()
	if len(entries) != 0 {
		t.Fatalf("logged entries = %d, want 0", len(entries))
	}
}

func TestLogging_MultipleSingleIPHeaders_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = mustProxyPrefixesFromAddrs(t, netip.MustParseAddr("1.1.1.1"))
	cfg.Sources = []Source{SourceXRealIP}
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("1.1.1.1:8080", "/test/multiple-single-ip-headers")
	req.Header.Add("X-Real-IP", "8.8.8.8")
	req.Header.Add("X-Real-IP", "9.9.9.9")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail for multiple single-IP headers")
	}
	if !errors.Is(err, ErrMultipleSingleIPHeaders) {
		t.Fatalf("error = %v, want ErrMultipleSingleIPHeaders", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventMultipleHeaders, SourceXRealIP, "/test/multiple-single-ip-headers", "1.1.1.1:8080")
	assertAttr(t, entry.attrs, "header", "X-Real-Ip")
	assertAttr(t, entry.attrs, "header_count", 2)
}

func TestLogging_ChainTooLong_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = mustProxyPrefixesFromAddrs(t, netip.MustParseAddr("1.1.1.1"))
	cfg.Sources = []Source{SourceXForwardedFor}
	cfg.MaxChainLength = 2
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("1.1.1.1:8080", "/test/chain-too-long")
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9, 4.4.4.4")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail for overlong X-Forwarded-For chain")
	}
	if !errors.Is(err, ErrChainTooLong) {
		t.Fatalf("error = %v, want ErrChainTooLong", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventChainTooLong, SourceXForwardedFor, "/test/chain-too-long", "1.1.1.1:8080")
	assertAttr(t, entry.attrs, "chain_length", 3)
	assertAttr(t, entry.attrs, "max_length", 2)
}

func TestLogging_TooFewTrustedProxies_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 2
	cfg.MaxTrustedProxies = 3
	cfg.Sources = []Source{SourceXForwardedFor}
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("10.0.0.1:8080", "/test/proxy-count")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail for too few trusted proxies")
	}
	if !errors.Is(err, ErrTooFewTrustedProxies) {
		t.Fatalf("error = %v, want ErrTooFewTrustedProxies", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventTooFewTrustedProxies, SourceXForwardedFor, "/test/proxy-count", "10.0.0.1:8080")
	assertAttr(t, entry.attrs, "trusted_proxy_count", 1)
	assertAttr(t, entry.attrs, "min_trusted_proxies", 2)
	assertAttr(t, entry.attrs, "max_trusted_proxies", 3)
}

func TestLogging_NoTrustedProxies_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 3
	cfg.Sources = []Source{SourceXForwardedFor}
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("10.0.0.1:8080", "/test/no-trusted-proxies")
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail when no trusted proxies are present in XFF")
	}
	if !errors.Is(err, ErrNoTrustedProxies) {
		t.Fatalf("error = %v, want ErrNoTrustedProxies", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventNoTrustedProxies, SourceXForwardedFor, "/test/no-trusted-proxies", "10.0.0.1:8080")
	assertAttr(t, entry.attrs, "trusted_proxy_count", 0)
	assertAttr(t, entry.attrs, "min_trusted_proxies", 1)
	assertAttr(t, entry.attrs, "max_trusted_proxies", 3)
}

func TestLogging_TooManyTrustedProxies_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 1
	cfg.Sources = []Source{SourceXForwardedFor}
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("10.0.0.2:8080", "/test/too-many-proxies")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1, 10.0.0.2")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail for too many trusted proxies")
	}
	if !errors.Is(err, ErrTooManyTrustedProxies) {
		t.Fatalf("error = %v, want ErrTooManyTrustedProxies", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventTooManyTrustedProxies, SourceXForwardedFor, "/test/too-many-proxies", "10.0.0.2:8080")
	assertAttr(t, entry.attrs, "trusted_proxy_count", 2)
	assertAttr(t, entry.attrs, "min_trusted_proxies", 1)
	assertAttr(t, entry.attrs, "max_trusted_proxies", 1)
}

func TestLogging_UntrustedProxy_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 3
	cfg.Sources = []Source{SourceXForwardedFor}
	extractor := mustNewExtractor(t, cfg)

	req := newTestRequest("8.8.8.8:8080", "/test/untrusted-proxy")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail for untrusted proxy")
	}
	if !errors.Is(err, ErrUntrustedProxy) {
		t.Fatalf("error = %v, want ErrUntrustedProxy", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventUntrustedProxy, SourceXForwardedFor, "/test/untrusted-proxy", "8.8.8.8:8080")
}

func TestLogging_MalformedForwarded_EmitsWarning(t *testing.T) {
	logger := &capturedLogger{}

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = mustProxyPrefixesFromAddrs(t, netip.MustParseAddr("1.1.1.1"))
	cfg.Sources = []Source{SourceForwarded, SourceRemoteAddr}
	extractor := mustNewExtractor(t, cfg)

	tests := []struct {
		name      string
		forwarded string
		path      string
	}{
		{name: "unterminated quoted value", forwarded: "for=\"1.1.1.1", path: "/test/malformed-forwarded/unterminated"},
		{name: "empty header value", forwarded: "", path: "/test/malformed-forwarded/empty"},
		{name: "empty element between commas", forwarded: "for=1.1.1.1,, for=8.8.8.8", path: "/test/malformed-forwarded/empty-element"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger.clear()

			req := newTestRequest("1.1.1.1:8080", tt.path)
			req.Header.Set("Forwarded", tt.forwarded)

			result, err := extractor.Extract(req)
			if err == nil && result.IP.IsValid() {
				t.Fatal("expected extraction to fail closed on malformed Forwarded")
			}
			if !errors.Is(err, ErrInvalidForwardedHeader) {
				t.Fatalf("error = %v, want ErrInvalidForwardedHeader", err)
			}
			if result.Source != SourceForwarded {
				t.Fatalf("source = %q, want %q", result.Source, SourceForwarded)
			}

			entries := logger.snapshot()
			if len(entries) != 1 {
				t.Fatalf("logged entries = %d, want 1", len(entries))
			}

			entry := entries[0]
			assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventMalformedForwarded, SourceForwarded, tt.path, "1.1.1.1:8080")
		})
	}
}

func TestExtractInput_UsesInputContextInLogs(t *testing.T) {
	logger := &capturedLogger{}

	cfg := defaultOptions()
	cfg.Logger = logger
	cfg.TrustedProxyPrefixes = mustProxyPrefixesFromAddrs(t, netip.MustParseAddr("1.1.1.1"))
	cfg.Sources = []Source{SourceXForwardedFor}
	cfg.MaxChainLength = 1
	extractor := mustNewExtractor(t, cfg)

	ctx := context.WithValue(context.Background(), loggerTestContextKey("trace_id"), "trace-from-input")
	headers := HeaderValuesFunc(func(name string) []string {
		if name == "X-Forwarded-For" {
			return []string{"8.8.8.8", "9.9.9.9"}
		}
		return nil
	})

	result, err := extractor.ExtractInput(Input{
		Context:    ctx,
		RemoteAddr: "1.1.1.1:8080",
		Headers:    headers,
	})
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction failure for overlong X-Forwarded-For chain")
	}
	if !errors.Is(err, ErrChainTooLong) {
		t.Fatalf("error = %v, want ErrChainTooLong", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	if got := entry.ctx.Value(loggerTestContextKey("trace_id")); got != "trace-from-input" {
		t.Fatalf("trace context value = %v, want %q", got, "trace-from-input")
	}

	assertCommonSecurityWarningAttrs(t, entry.attrs, SecurityEventChainTooLong, SourceXForwardedFor, "", "1.1.1.1:8080")
}

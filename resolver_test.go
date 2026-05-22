package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
)

type resolvedEvent struct {
	ctx    context.Context
	result Result
}

type recordingObserver struct {
	events []resolvedEvent
}

func (o *recordingObserver) OnResolved(ctx context.Context, result Result) {
	o.events = append(o.events, resolvedEvent{ctx: ctx, result: result})
}

func TestResolve_NilInputs(t *testing.T) {
	resolver, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if result := resolver.Resolve(nil); !errors.Is(result.Err, ErrNilRequest) {
		t.Fatalf("Resolve(nil) error = %v, want ErrNilRequest", result.Err)
	}

	var nilResolver *Resolver
	if result := nilResolver.Resolve(&http.Request{}); !errors.Is(result.Err, errNilResolverExtractor) {
		t.Fatalf("nil resolver error = %v, want errNilResolverExtractor", result.Err)
	}
}

func TestResolve_NilRequestObserved(t *testing.T) {
	observer := &recordingObserver{}
	resolver, err := New(WithObserver(observer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := resolver.Resolve(nil)
	if !errors.Is(result.Err, ErrNilRequest) {
		t.Fatalf("Resolve(nil) error = %v, want ErrNilRequest", result.Err)
	}
	if len(observer.events) != 1 {
		t.Fatalf("observer events = %d, want 1", len(observer.events))
	}
	event := observer.events[0]
	if event.ctx == nil {
		t.Fatal("observer context = nil, want non-nil")
	}
	if !errors.Is(event.result.Err, ErrNilRequest) {
		t.Fatalf("observer result error = %v, want ErrNilRequest", event.result.Err)
	}
}

func TestResolveOperational_NilRequestObservedWithoutFallback(t *testing.T) {
	observer := &recordingObserver{}
	resolver, err := New(WithObserver(observer))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := resolver.ResolveOperational(nil, StaticFallback(netip.MustParseAddr("0.0.0.0")))
	if !errors.Is(result.Err, ErrNilRequest) {
		t.Fatalf("ResolveOperational(nil) error = %v, want ErrNilRequest", result.Err)
	}
	if result.FallbackUsed {
		t.Fatal("ResolveOperational(nil) used fallback")
	}
	if len(observer.events) != 1 {
		t.Fatalf("observer events = %d, want 1", len(observer.events))
	}
	event := observer.events[0]
	if event.ctx == nil {
		t.Fatal("observer context = nil, want non-nil")
	}
	if !errors.Is(event.result.Err, ErrNilRequest) {
		t.Fatalf("observer result error = %v, want ErrNilRequest", event.result.Err)
	}
	if event.result.FallbackUsed {
		t.Fatal("observer result used fallback")
	}
}

func TestResolve_RemoteAddrDefault(t *testing.T) {
	resolver, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	result := resolver.Resolve(&http.Request{RemoteAddr: "8.8.8.8:443", Header: make(http.Header)})
	if result.Err != nil {
		t.Fatalf("Resolve() error = %v", result.Err)
	}
	if result.IP != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("Resolve() IP = %v, want 8.8.8.8", result.IP)
	}
	if result.Source != SourceRemoteAddr {
		t.Fatalf("Resolve() Source = %v, want %v", result.Source, SourceRemoteAddr)
	}
}

func TestFallbackReasonString(t *testing.T) {
	tests := []struct {
		reason FallbackReason
		want   string
	}{
		{reason: FallbackReasonNone, want: "none"},
		{reason: FallbackReasonUntrustedProxy, want: "untrusted_proxy"},
		{reason: FallbackReasonMalformedHeader, want: "malformed_header"},
		{reason: FallbackReasonSourceUnavailable, want: "source_unavailable"},
		{reason: FallbackReasonInvalidIP, want: "invalid_ip"},
		{reason: FallbackReason(255), want: "unknown"},
	}

	for _, tt := range tests {
		if got := tt.reason.String(); got != tt.want {
			t.Fatalf("FallbackReason(%d).String() = %q, want %q", tt.reason, got, tt.want)
		}
	}
}

func TestResolveOperational_ContextErrorsRemainTerminal(t *testing.T) {
	resolver, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "/", nil)
	if err != nil {
		t.Fatalf("NewRequestWithContext() error = %v", err)
	}
	req.RemoteAddr = "8.8.8.8:443"

	result := resolver.ResolveOperational(req, StaticFallback(netip.MustParseAddr("0.0.0.0")))
	if !errors.Is(result.Err, context.Canceled) {
		t.Fatalf("ResolveOperational() error = %v, want context.Canceled", result.Err)
	}
	if result.FallbackUsed {
		t.Fatal("ResolveOperational() used fallback for context cancellation")
	}
}

func TestNewOptionsResolveAndOperationalFallback(t *testing.T) {
	resolver, err := New(
		WithTrustedProxies(netip.MustParsePrefix("127.0.0.0/8")),
		WithSources(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{RemoteAddr: "203.0.113.10:443", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	strict := resolver.Resolve(req)
	if strict.Err == nil {
		t.Fatal("Resolve() error = nil, want untrusted proxy error")
	}

	operational := resolver.ResolveOperational(req, StaticFallback(netip.MustParseAddr("0.0.0.0")))
	if operational.Err != nil {
		t.Fatalf("ResolveOperational() error = %v, want nil", operational.Err)
	}
	if !operational.FallbackUsed {
		t.Fatal("ResolveOperational() FallbackUsed = false, want true")
	}
	if operational.FallbackReason != FallbackReasonUntrustedProxy {
		t.Fatalf("FallbackReason = %v, want %v", operational.FallbackReason, FallbackReasonUntrustedProxy)
	}
	if operational.Classify() != ResultFallback {
		t.Fatalf("Classify() = %v, want %v", operational.Classify(), ResultFallback)
	}
}

func TestMiddlewareStoresResultAndPassesThroughOnError(t *testing.T) {
	resolver, err := New(
		WithTrustedProxies(netip.MustParsePrefix("127.0.0.0/8")),
		WithSources(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	called := false
	handler := resolver.Middleware()(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		called = true
		result, ok := FromContext(req.Context())
		if !ok {
			t.Fatal("FromContext() ok = false, want true")
		}
		if result.Err == nil {
			t.Fatal("middleware result error = nil, want strict error")
		}
		w.WriteHeader(http.StatusAccepted)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.10:443"
	req.Header.Set("X-Forwarded-For", "8.8.8.8")
	rr := httptest.NewRecorder()

	handler.ServeHTTP(rr, req)
	if !called {
		t.Fatal("next handler was not called")
	}
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want %d", rr.Code, http.StatusAccepted)
	}
}

func TestResolveInputAndHeaders(t *testing.T) {
	resolver, err := New(
		WithTrustedProxies(netip.MustParsePrefix("127.0.0.0/8")),
		WithSources(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	headers := http.Header{"X-Forwarded-For": {"8.8.8.8"}}
	result := resolver.ResolveHeaders(context.Background(), "127.0.0.1:12345", headers)
	if result.Err != nil {
		t.Fatalf("ResolveHeaders() error = %v", result.Err)
	}
	if result.IP != netip.MustParseAddr("8.8.8.8") {
		t.Fatalf("ResolveHeaders() IP = %v, want 8.8.8.8", result.IP)
	}
}

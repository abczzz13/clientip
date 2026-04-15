package clientip

import (
	"net/netip"
	"sync"
	"testing"
)

type mockMetrics struct {
	mu             sync.Mutex
	successCount   map[string]int
	failureCount   map[string]int
	securityEvents map[string]int
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		successCount:   make(map[string]int),
		failureCount:   make(map[string]int),
		securityEvents: make(map[string]int),
	}
}

func (m *mockMetrics) RecordExtractionSuccess(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successCount[source]++
}

func (m *mockMetrics) RecordExtractionFailure(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failureCount[source]++
}

func (m *mockMetrics) RecordSecurityEvent(event string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.securityEvents[event]++
}

func (m *mockMetrics) getSuccessCount(source string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.successCount[source]
}

func (m *mockMetrics) getFailureCount(source string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.failureCount[source]
}

func (m *mockMetrics) getSecurityEventCount(event string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.securityEvents[event]
}

func TestMetrics_ExtractionSuccess(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("1.1.1.1:12345", "")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Errorf("Extract() failed: %v", err)
	}

	if got := metrics.getSuccessCount(SourceRemoteAddr); got != 1 {
		t.Errorf("success count for %s = %d, want 1", SourceRemoteAddr, got)
	}
}

func TestMetrics_ExtractionFailure(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("127.0.0.1:8080", "")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Errorf("Extract() should have failed for loopback IP")
	}

	if got := metrics.getFailureCount(SourceRemoteAddr); got != 1 {
		t.Errorf("failure count for %s = %d, want 1", SourceRemoteAddr, got)
	}
}

func TestMetrics_SecurityEvent_InvalidIP(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("127.0.0.1:8080", "")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventInvalidIP); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventInvalidIP, got)
	}
}

func TestMetrics_SecurityEvent_PrivateIP(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		AllowPrivateIPs(false),
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("192.168.1.1:8080", "")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventPrivateIP); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventPrivateIP, got)
	}
}

func TestMetrics_SecurityEvent_ReservedIP(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("198.51.100.1:8080", "")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventReservedIP); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventReservedIP, got)
	}
}

func TestMetrics_SecurityEvent_ReservedIP_Allowlisted(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		AllowReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24")),
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("198.51.100.1:8080", "")

	if _, err := extractor.Extract(req); err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if got := metrics.getSecurityEventCount(securityEventReservedIP); got != 0 {
		t.Errorf("security event count for %s = %d, want 0", securityEventReservedIP, got)
	}
	if got := metrics.getSuccessCount(SourceRemoteAddr); got != 1 {
		t.Errorf("success count for %s = %d, want 1", SourceRemoteAddr, got)
	}
}

func TestMetrics_MultipleXFFHeaders_DoNotEmitSecurityEvent(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("1.1.1.1:8080", "")
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "1.1.1.1")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected extraction success, got error: %v", err)
	}

	if got := metrics.getSecurityEventCount(securityEventMultipleHeaders); got != 0 {
		t.Errorf("security event count for %s = %d, want 0", securityEventMultipleHeaders, got)
	}

	if got := metrics.getSuccessCount(SourceXForwardedFor); got != 1 {
		t.Errorf("success count for %s = %d, want 1", SourceXForwardedFor, got)
	}

	if got := metrics.getFailureCount(SourceXForwardedFor); got != 0 {
		t.Errorf("failure count for %s = %d, want 0", SourceXForwardedFor, got)
	}
}

func TestMetrics_SecurityEvent_MultipleSingleIPHeaders(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		Priority(SourceXRealIP),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("1.1.1.1:8080", "")
	req.Header.Add("X-Real-IP", "8.8.8.8")
	req.Header.Add("X-Real-IP", "9.9.9.9")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail for multiple single-IP headers")
	}

	if got := metrics.getSecurityEventCount(securityEventMultipleHeaders); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventMultipleHeaders, got)
	}

	if got := metrics.getFailureCount(SourceXRealIP); got != 1 {
		t.Errorf("failure count for %s = %d, want 1", SourceXRealIP, got)
	}
}

func TestMetrics_SecurityEvent_TooFewTrustedProxies(t *testing.T) {
	metrics := newMockMetrics()
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")
	extractor, err := New(
		TrustProxyPrefixes(cidrs...),
		MinTrustedProxies(2),
		MaxTrustedProxies(3),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("10.0.0.1:8080", "")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventTooFewTrustedProxies); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventTooFewTrustedProxies, got)
	}
}

func TestMetrics_SecurityEvent_NoTrustedProxies(t *testing.T) {
	metrics := newMockMetrics()
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")
	extractor, err := New(
		TrustProxyPrefixes(cidrs...),
		MinTrustedProxies(1),
		MaxTrustedProxies(3),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("10.0.0.1:8080", "")
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventNoTrustedProxies); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventNoTrustedProxies, got)
	}
}

func TestMetrics_SecurityEvent_TooManyTrustedProxies(t *testing.T) {
	metrics := newMockMetrics()
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")
	extractor, err := New(
		TrustProxyPrefixes(cidrs...),
		MinTrustedProxies(1),
		MaxTrustedProxies(1),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("10.0.0.2:8080", "")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1, 10.0.0.2")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventTooManyTrustedProxies); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventTooManyTrustedProxies, got)
	}
}

func TestMetrics_SecurityEvent_UntrustedProxy(t *testing.T) {
	metrics := newMockMetrics()
	cidrs := mustParseCIDRs(t, "10.0.0.0/8")
	extractor, err := New(
		TrustProxyPrefixes(cidrs...),
		MinTrustedProxies(1),
		MaxTrustedProxies(3),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("8.8.8.8:8080", "")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventUntrustedProxy); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventUntrustedProxy, got)
	}
}

func TestMetrics_SecurityEvent_ChainTooLong(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		MaxChainLength(5),
		WithMetrics(metrics),
		TrustLoopbackProxy(),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("127.0.0.1:8080", "")
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventChainTooLong); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventChainTooLong, got)
	}
}

func TestMetrics_SecurityEvent_MalformedForwarded(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		Priority(SourceForwarded, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("1.1.1.1:8080", "")
	req.Header.Set("Forwarded", "for=\"1.1.1.1")

	_, _ = extractor.Extract(req)

	if got := metrics.getSecurityEventCount(securityEventMalformedForwarded); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventMalformedForwarded, got)
	}
}

func TestMetrics_ForwardedSourceSuccess(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustLoopbackProxy(),
		Priority(SourceForwarded),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := newTestRequest("127.0.0.1:8080", "")
	req.Header.Set("Forwarded", "for=1.1.1.1")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("Extract() failed: %v", err)
	}

	if got := metrics.getSuccessCount(SourceForwarded); got != 1 {
		t.Errorf("success count for %s = %d, want 1", SourceForwarded, got)
	}
}

func TestMetrics_MultipleExtractions(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustLoopbackProxy(),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Successful extraction
	req1 := newTestRequest("1.1.1.1:12345", "")
	_, _ = extractor.Extract(req1)

	// Another successful extraction
	req2 := newTestRequest("8.8.8.8:8080", "")
	_, _ = extractor.Extract(req2)

	// Failed extraction
	req3 := newTestRequest("127.0.0.1:8080", "")
	_, _ = extractor.Extract(req3)

	if got := metrics.getSuccessCount(SourceRemoteAddr); got != 2 {
		t.Errorf("success count = %d, want 2", got)
	}

	if got := metrics.getFailureCount(SourceRemoteAddr); got != 1 {
		t.Errorf("failure count = %d, want 1", got)
	}
}

func TestMetrics_DifferentSources(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustLoopbackProxy(),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// Success from X-Forwarded-For
	req1 := newTestRequest("127.0.0.1:8080", "")
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	_, _ = extractor.Extract(req1)

	// Success from RemoteAddr
	req2 := newTestRequest("8.8.8.8:8080", "")
	_, _ = extractor.Extract(req2)

	if got := metrics.getSuccessCount(SourceXForwardedFor); got != 1 {
		t.Errorf("XFF success count = %d, want 1", got)
	}

	if got := metrics.getSuccessCount(SourceRemoteAddr); got != 1 {
		t.Errorf("RemoteAddr success count = %d, want 1", got)
	}
}

func TestMetrics_ConcurrentAccess(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	const goroutines = 50
	done := make(chan bool, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			req := newTestRequest("1.1.1.1:12345", "")
			_, _ = extractor.Extract(req)
			done <- true
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	if got := metrics.getSuccessCount(SourceRemoteAddr); got != goroutines {
		t.Errorf("success count = %d, want %d", got, goroutines)
	}
}

func TestNoopMetrics(t *testing.T) {
	noop := noopMetrics{}

	// Should not panic
	noop.RecordExtractionSuccess("test")
	noop.RecordExtractionFailure("test")
	noop.RecordSecurityEvent("test")
}

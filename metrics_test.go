package clientip

import (
	"net/http"
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

	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}

	result := extractor.ExtractIP(req)
	if !result.Valid() {
		t.Errorf("ExtractIP() failed: %v", result.Err)
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

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Errorf("ExtractIP() should have failed for loopback IP")
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

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}

	extractor.ExtractIP(req)

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

	req := &http.Request{
		RemoteAddr: "192.168.1.1:8080",
		Header:     make(http.Header),
	}

	extractor.ExtractIP(req)

	if got := metrics.getSecurityEventCount(securityEventPrivateIP); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventPrivateIP, got)
	}
}

func TestMetrics_SecurityEvent_MultipleHeaders(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustProxyIP("1.1.1.1"),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "1.1.1.1")

	extractor.ExtractIP(req)

	if got := metrics.getSecurityEventCount(securityEventMultipleHeaders); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventMultipleHeaders, got)
	}
}

func TestMetrics_SecurityEvent_TooFewTrustedProxies(t *testing.T) {
	metrics := newMockMetrics()
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, err := New(
		TrustedProxies(cidrs, 2, 3),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	extractor.ExtractIP(req)

	if got := metrics.getSecurityEventCount(securityEventTooFewTrustedProxies); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventTooFewTrustedProxies, got)
	}
}

func TestMetrics_SecurityEvent_NoTrustedProxies(t *testing.T) {
	metrics := newMockMetrics()
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, err := New(
		TrustedProxies(cidrs, 1, 3),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	extractor.ExtractIP(req)

	if got := metrics.getSecurityEventCount(securityEventNoTrustedProxies); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventNoTrustedProxies, got)
	}
}

func TestMetrics_SecurityEvent_TooManyTrustedProxies(t *testing.T) {
	metrics := newMockMetrics()
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, err := New(
		TrustedProxies(cidrs, 1, 1),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.2:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1, 10.0.0.2")

	extractor.ExtractIP(req)

	if got := metrics.getSecurityEventCount(securityEventTooManyTrustedProxies); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventTooManyTrustedProxies, got)
	}
}

func TestMetrics_SecurityEvent_UntrustedProxy(t *testing.T) {
	metrics := newMockMetrics()
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, err := New(
		TrustedProxies(cidrs, 1, 3),
		WithMetrics(metrics),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	extractor.ExtractIP(req)

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

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6")

	extractor.ExtractIP(req)

	if got := metrics.getSecurityEventCount(securityEventChainTooLong); got != 1 {
		t.Errorf("security event count for %s = %d, want 1", securityEventChainTooLong, got)
	}
}

func TestMetrics_SecurityEvent_MalformedForwarded(t *testing.T) {
	metrics := newMockMetrics()
	extractor, err := New(
		WithMetrics(metrics),
		TrustProxyIP("1.1.1.1"),
		Priority(SourceForwarded, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", "for=\"1.1.1.1")

	extractor.ExtractIP(req)

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

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", "for=1.1.1.1")

	result := extractor.ExtractIP(req)
	if !result.Valid() {
		t.Fatalf("ExtractIP() failed: %v", result.Err)
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
	req1 := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}
	extractor.ExtractIP(req1)

	// Another successful extraction
	req2 := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
	}
	extractor.ExtractIP(req2)

	// Failed extraction
	req3 := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	extractor.ExtractIP(req3)

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
	req1 := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req1.Header.Set("X-Forwarded-For", "1.1.1.1")
	extractor.ExtractIP(req1)

	// Success from RemoteAddr
	req2 := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
	}
	extractor.ExtractIP(req2)

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
			req := &http.Request{
				RemoteAddr: "1.1.1.1:12345",
				Header:     make(http.Header),
			}
			extractor.ExtractIP(req)
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

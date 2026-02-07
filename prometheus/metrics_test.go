package prometheus

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abczzz13/clientip"
	prom "github.com/prometheus/client_golang/prometheus"
)

type mockMetrics struct {
	mu           sync.Mutex
	successCount map[string]int
}

func newMockMetrics() *mockMetrics {
	return &mockMetrics{
		successCount: make(map[string]int),
	}
}

func (m *mockMetrics) RecordExtractionSuccess(source string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.successCount[source]++
}

func (m *mockMetrics) RecordExtractionFailure(string) {}

func (m *mockMetrics) RecordSecurityEvent(string) {}

func (m *mockMetrics) getSuccessCount(source string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.successCount[source]
}

func TestWithMetrics_Option(t *testing.T) {
	extractor, err := clientip.New(
		WithMetrics(),
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
		t.Fatalf("ExtractIP() error = %v", result.Err)
	}
}

func TestWithRegisterer_Option(t *testing.T) {
	registry := prom.NewRegistry()

	extractor, err := clientip.New(
		WithRegisterer(registry),
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
		t.Fatalf("ExtractIP() error = %v", result.Err)
	}

	if got := counterValue(registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr, "result": "success"}); got != 1 {
		t.Fatalf("ip_extraction_total counter = %v, want 1", got)
	}
}

func TestMetricsOptions_Precedence_LastWins(t *testing.T) {
	t.Run("custom metrics after prometheus option", func(t *testing.T) {
		registry := prom.NewRegistry()
		customMetrics := newMockMetrics()

		extractor, err := clientip.New(
			WithRegisterer(registry),
			clientip.WithMetrics(customMetrics),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "1.1.1.1:12345",
			Header:     make(http.Header),
		}
		extractor.ExtractIP(req)

		if got := customMetrics.getSuccessCount(clientip.SourceRemoteAddr); got != 1 {
			t.Fatalf("custom metrics success count = %d, want 1", got)
		}
		if got := counterValue(registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr, "result": "success"}); got != 0 {
			t.Fatalf("prometheus counter = %v, want 0", got)
		}
	})

	t.Run("prometheus option after custom metrics", func(t *testing.T) {
		registry := prom.NewRegistry()
		customMetrics := newMockMetrics()

		extractor, err := clientip.New(
			clientip.WithMetrics(customMetrics),
			WithRegisterer(registry),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "1.1.1.1:12345",
			Header:     make(http.Header),
		}
		extractor.ExtractIP(req)

		if got := customMetrics.getSuccessCount(clientip.SourceRemoteAddr); got != 0 {
			t.Fatalf("custom metrics success count = %d, want 0", got)
		}
		if got := counterValue(registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr, "result": "success"}); got != 1 {
			t.Fatalf("prometheus counter = %v, want 1", got)
		}
	})
}

func TestNewWithRegisterer_Creation(t *testing.T) {
	registry := prom.NewRegistry()
	metricsA, err := NewWithRegisterer(registry)
	if err != nil {
		t.Fatalf("NewWithRegisterer() error = %v", err)
	}

	metricsB, err := NewWithRegisterer(registry)
	if err != nil {
		t.Fatalf("second NewWithRegisterer() error = %v", err)
	}

	if metricsA == nil || metricsB == nil {
		t.Fatal("expected non-nil prometheus metrics instances")
	}

	metricsA.RecordExtractionSuccess(clientip.SourceRemoteAddr)
	metricsB.RecordSecurityEvent("multiple_headers")
}

type failingRegisterer struct {
	err error
}

func (r failingRegisterer) Register(prom.Collector) error {
	return r.err
}

func (r failingRegisterer) MustRegister(...prom.Collector) {}

func (r failingRegisterer) Unregister(prom.Collector) bool {
	return false
}

func TestNewWithRegisterer_RegisterError(t *testing.T) {
	registerErr := errors.New("register failed")

	_, err := NewWithRegisterer(failingRegisterer{err: registerErr})
	if !errors.Is(err, registerErr) {
		t.Fatalf("error = %v, want wrapped register error", err)
	}
}

func TestNewWithRegisterer_IncompatibleCollectorType(t *testing.T) {
	registry := prom.NewRegistry()
	gauge := prom.NewGaugeVec(
		prom.GaugeOpts{
			Name: "ip_extraction_total",
			Help: "Total number of IP extraction attempts by source (forwarded, x-forwarded-for, x-real-ip, remote-addr) and result (success, invalid).",
		},
		[]string{"source", "result"},
	)
	if err := registry.Register(gauge); err != nil {
		t.Fatalf("registry.Register() error = %v", err)
	}

	_, err := NewWithRegisterer(registry)
	if err == nil {
		t.Fatal("expected error for incompatible existing collector type")
	}
	if !strings.Contains(err.Error(), "incompatible collector type") {
		t.Fatalf("error = %q, want incompatible collector type message", err.Error())
	}
}

func TestWithRegisterer_OptionError(t *testing.T) {
	registerErr := errors.New("register failed")
	cfg := &clientip.Config{}

	err := WithRegisterer(failingRegisterer{err: registerErr})(cfg)
	if !errors.Is(err, registerErr) {
		t.Fatalf("error = %v, want wrapped register error", err)
	}
}

func counterValue(registry *prom.Registry, metricName string, labels map[string]string) float64 {
	metricFamilies, err := registry.Gather()
	if err != nil {
		return 0
	}

	for _, family := range metricFamilies {
		if family.GetName() != metricName {
			continue
		}

		for _, metric := range family.GetMetric() {
			metricLabels := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				metricLabels[pair.GetName()] = pair.GetValue()
			}

			if !labelsMatch(metricLabels, labels) {
				continue
			}
			if metric.GetCounter() == nil {
				return 0
			}
			return metric.GetCounter().GetValue()
		}
	}

	return 0
}

func labelsMatch(metricLabels, labels map[string]string) bool {
	for labelName, labelValue := range labels {
		if metricLabels[labelName] != labelValue {
			return false
		}
	}

	return true
}

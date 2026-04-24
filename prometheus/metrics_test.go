package prometheus_test

import (
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abczzz13/clientip"
	clientipprom "github.com/abczzz13/clientip/prometheus"
	"github.com/google/go-cmp/cmp"
	prom "github.com/prometheus/client_golang/prometheus"
)

var defaultRegistryMu sync.Mutex

func withIsolatedDefaultRegistry(t *testing.T) *prom.Registry {
	t.Helper()
	defaultRegistryMu.Lock()

	registry := prom.NewRegistry()
	originalRegisterer := prom.DefaultRegisterer
	originalGatherer := prom.DefaultGatherer
	prom.DefaultRegisterer = registry
	prom.DefaultGatherer = registry

	t.Cleanup(func() {
		prom.DefaultRegisterer = originalRegisterer
		prom.DefaultGatherer = originalGatherer
		defaultRegistryMu.Unlock()
	})

	return registry
}

func TestIntegration_ExtractWithPrometheusMetrics(t *testing.T) {
	tests := []struct {
		name  string
		setup func(t *testing.T) (clientip.Config, *prom.Registry)
	}{
		{
			name: "default registerer via explicit metrics",
			setup: func(t *testing.T) (clientip.Config, *prom.Registry) {
				registry := withIsolatedDefaultRegistry(t)
				metrics, err := clientipprom.New()
				if err != nil {
					t.Fatalf("New() error = %v", err)
				}
				return clientip.Config{Metrics: metrics}, registry
			},
		},
		{
			name: "custom registerer via explicit metrics",
			setup: func(t *testing.T) (clientip.Config, *prom.Registry) {
				registry := prom.NewRegistry()
				metrics, err := clientipprom.NewWithRegisterer(registry)
				if err != nil {
					t.Fatalf("NewWithRegisterer() error = %v", err)
				}
				return clientip.Config{Metrics: metrics}, registry
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, registry := tt.setup(t)

			extractor, err := clientip.New(cfg)
			if err != nil {
				t.Fatalf("clientip.New() error = %v", err)
			}

			req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}
			if _, err := extractor.Extract(req); err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			got := mustCounterValue(t, registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr.String(), "result": "success"})
			if got != 1 {
				t.Fatalf("ip_extraction_total counter = %v, want 1", got)
			}
		})
	}
}

func TestNewWithRegisterer_Creation(t *testing.T) {
	registry := prom.NewRegistry()
	metricsA, err := clientipprom.NewWithRegisterer(registry)
	if err != nil {
		t.Fatalf("NewWithRegisterer() error = %v", err)
	}

	metricsB, err := clientipprom.NewWithRegisterer(registry)
	if err != nil {
		t.Fatalf("second NewWithRegisterer() error = %v", err)
	}

	if metricsA == nil || metricsB == nil {
		t.Fatal("expected non-nil prometheus metrics instances")
	}

	metricsA.RecordExtractionSuccess(clientip.SourceRemoteAddr.String())
	metricsB.RecordSecurityEvent("multiple_headers")
}

func TestNewWithRegisterer_TypedNilUsesDefaultRegisterer(t *testing.T) {
	registry := withIsolatedDefaultRegistry(t)

	var registerer *prom.Registry
	metrics, err := clientipprom.NewWithRegisterer(registerer)
	if err != nil {
		t.Fatalf("NewWithRegisterer() error = %v", err)
	}

	extractor, err := clientip.New(clientip.Config{Metrics: metrics})
	if err != nil {
		t.Fatalf("clientip.New() error = %v", err)
	}

	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}
	if _, err := extractor.Extract(req); err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	if got := mustCounterValue(t, registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr.String(), "result": "success"}); got != 1 {
		t.Fatalf("ip_extraction_total counter = %v, want 1", got)
	}
}

func TestPrometheusMetrics_RecordExtractionFailureCounter(t *testing.T) {
	tests := []struct {
		name string
		run  func(*clientipprom.PrometheusMetrics)
		want struct {
			Success counterObservation
			Invalid counterObservation
		}
	}{
		{
			name: "failure only increments invalid label",
			run: func(metrics *clientipprom.PrometheusMetrics) {
				metrics.RecordExtractionFailure(clientip.SourceRemoteAddr.String())
			},
			want: struct {
				Success counterObservation
				Invalid counterObservation
			}{
				Success: counterObservation{Value: 0, Found: false},
				Invalid: counterObservation{Value: 1, Found: true},
			},
		},
		{
			name: "mixed success and failure counters are independent",
			run: func(metrics *clientipprom.PrometheusMetrics) {
				metrics.RecordExtractionSuccess(clientip.SourceRemoteAddr.String())
				metrics.RecordExtractionFailure(clientip.SourceRemoteAddr.String())
				metrics.RecordExtractionFailure(clientip.SourceRemoteAddr.String())
			},
			want: struct {
				Success counterObservation
				Invalid counterObservation
			}{
				Success: counterObservation{Value: 1, Found: true},
				Invalid: counterObservation{Value: 2, Found: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prom.NewRegistry()
			metrics, err := clientipprom.NewWithRegisterer(registry)
			if err != nil {
				t.Fatalf("NewWithRegisterer() error = %v", err)
			}

			tt.run(metrics)

			got := struct {
				Success counterObservation
				Invalid counterObservation
			}{
				Success: observeCounterValue(t, registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr.String(), "result": "success"}),
				Invalid: observeCounterValue(t, registry, "ip_extraction_total", map[string]string{"source": clientip.SourceRemoteAddr.String(), "result": "invalid"}),
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("counter mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPrometheusMetrics_RecordSecurityEventCounter(t *testing.T) {
	tests := []struct {
		name string
		run  func(*clientipprom.PrometheusMetrics)
		want struct {
			InvalidIP    counterObservation
			ChainTooLong counterObservation
		}
	}{
		{
			name: "single event increments matching label",
			run: func(metrics *clientipprom.PrometheusMetrics) {
				metrics.RecordSecurityEvent("invalid_ip")
			},
			want: struct {
				InvalidIP    counterObservation
				ChainTooLong counterObservation
			}{
				InvalidIP:    counterObservation{Value: 1, Found: true},
				ChainTooLong: counterObservation{Value: 0, Found: false},
			},
		},
		{
			name: "different event labels stay independent",
			run: func(metrics *clientipprom.PrometheusMetrics) {
				metrics.RecordSecurityEvent("invalid_ip")
				metrics.RecordSecurityEvent("chain_too_long")
				metrics.RecordSecurityEvent("chain_too_long")
			},
			want: struct {
				InvalidIP    counterObservation
				ChainTooLong counterObservation
			}{
				InvalidIP:    counterObservation{Value: 1, Found: true},
				ChainTooLong: counterObservation{Value: 2, Found: true},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := prom.NewRegistry()
			metrics, err := clientipprom.NewWithRegisterer(registry)
			if err != nil {
				t.Fatalf("NewWithRegisterer() error = %v", err)
			}

			tt.run(metrics)

			got := struct {
				InvalidIP    counterObservation
				ChainTooLong counterObservation
			}{
				InvalidIP:    observeCounterValue(t, registry, "ip_extraction_security_events_total", map[string]string{"event": "invalid_ip"}),
				ChainTooLong: observeCounterValue(t, registry, "ip_extraction_security_events_total", map[string]string{"event": "chain_too_long"}),
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("security event counter mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

type failOnRegisterCall struct {
	failAt int
	err    error
	calls  int
}

func (r *failOnRegisterCall) Register(prom.Collector) error {
	r.calls++
	if r.calls == r.failAt {
		return r.err
	}

	return nil
}

func (r *failOnRegisterCall) MustRegister(...prom.Collector) {}

func (r *failOnRegisterCall) Unregister(prom.Collector) bool {
	return false
}

func TestNewWithRegisterer_RegisterFailureByStep(t *testing.T) {
	baseErr := errors.New("register failed")

	tests := []struct {
		name       string
		failAt     int
		metricName string
	}{
		{name: "first metric registration fails", failAt: 1, metricName: "ip_extraction_total"},
		{name: "second metric registration fails", failAt: 2, metricName: "ip_extraction_security_events_total"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registerer := &failOnRegisterCall{failAt: tt.failAt, err: baseErr}
			_, err := clientipprom.NewWithRegisterer(registerer)

			got := struct {
				HasErr         bool
				WrapsBaseError bool
				HasMetricName  bool
			}{
				HasErr:         err != nil,
				WrapsBaseError: errors.Is(err, baseErr),
				HasMetricName:  err != nil && strings.Contains(err.Error(), tt.metricName),
			}

			want := struct {
				HasErr         bool
				WrapsBaseError bool
				HasMetricName  bool
			}{
				HasErr:         true,
				WrapsBaseError: true,
				HasMetricName:  true,
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("error result mismatch (-want +got):\n%s", diff)
			}
		})
	}
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

	_, err := clientipprom.NewWithRegisterer(failingRegisterer{err: registerErr})
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

	_, err := clientipprom.NewWithRegisterer(registry)
	if err == nil {
		t.Fatal("expected error for incompatible existing collector type")
	}
	if !strings.Contains(err.Error(), "incompatible collector type") {
		t.Fatalf("error = %q, want incompatible collector type message", err.Error())
	}
}

type counterObservation struct {
	Value float64
	Found bool
}

func observeCounterValue(t testing.TB, registry *prom.Registry, metricName string, labels map[string]string) counterObservation {
	t.Helper()

	value, found, err := lookupCounterValue(registry, metricName, labels)
	if err != nil {
		t.Fatalf("lookupCounterValue(%q, %v) error = %v", metricName, labels, err)
	}

	return counterObservation{Value: value, Found: found}
}

func mustCounterValue(t testing.TB, registry *prom.Registry, metricName string, labels map[string]string) float64 {
	t.Helper()

	value, found, err := lookupCounterValue(registry, metricName, labels)
	if err != nil {
		t.Fatalf("lookupCounterValue(%q, %v) error = %v", metricName, labels, err)
	}

	if !found {
		t.Fatalf("counter %q with labels %v not found", metricName, labels)
	}

	return value
}

func lookupCounterValue(registry *prom.Registry, metricName string, labels map[string]string) (float64, bool, error) {
	metricFamilies, err := registry.Gather()
	if err != nil {
		return 0, false, err
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
				return 0, false, fmt.Errorf("metric %q with labels %v is not a counter", metricName, labels)
			}
			return metric.GetCounter().GetValue(), true, nil
		}
	}

	return 0, false, nil
}

func labelsMatch(metricLabels, labels map[string]string) bool {
	for labelName, labelValue := range labels {
		if metricLabels[labelName] != labelValue {
			return false
		}
	}

	return true
}

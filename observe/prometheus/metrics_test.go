package prometheus_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/abczzz13/clientip"
	clientipprom "github.com/abczzz13/clientip/observe/prometheus"
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

func TestIntegration_ObserverRecordsResolution(t *testing.T) {
	registry := prom.NewRegistry()
	metrics, err := clientipprom.NewWithRegisterer(registry)
	if err != nil {
		t.Fatalf("NewWithRegisterer() error = %v", err)
	}

	resolver, err := clientip.New(clientip.WithObserver(metrics))
	if err != nil {
		t.Fatalf("clientip.New() error = %v", err)
	}

	result := resolver.Resolve(&http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)})
	if result.Err != nil {
		t.Fatalf("Resolve() error = %v", result.Err)
	}

	got := mustCounterValue(t, registry, "ip_resolution_total", map[string]string{
		"source": clientip.SourceRemoteAddr.String(),
		"result": clientip.ResultSuccess.String(),
	})
	if got != 1 {
		t.Fatalf("ip_resolution_total counter = %v, want 1", got)
	}
}

func TestIntegration_ObserverRecordsFallback(t *testing.T) {
	registry := prom.NewRegistry()
	metrics, err := clientipprom.NewWithRegisterer(registry)
	if err != nil {
		t.Fatalf("NewWithRegisterer() error = %v", err)
	}

	resolver, err := clientip.New(
		clientip.WithObserver(metrics),
		clientip.WithTrustedProxies(clientip.LoopbackProxyPrefixes()...),
		clientip.WithSources(clientip.SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("clientip.New() error = %v", err)
	}

	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}
	result := resolver.ResolveOperational(req, clientip.RemoteAddrFallback())
	if result.Err != nil || !result.FallbackUsed {
		t.Fatalf("ResolveOperational() = %+v, want fallback success", result)
	}

	got := mustCounterValue(t, registry, "ip_resolution_total", map[string]string{
		"source": clientip.SourceRemoteAddr.String(),
		"result": clientip.ResultFallback.String(),
	})
	if got != 1 {
		t.Fatalf("ip_resolution_total fallback counter = %v, want 1", got)
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

	metricsA.OnResolved(context.Background(), clientip.Result{Extraction: clientip.Extraction{Source: clientip.SourceRemoteAddr}})
	metricsB.OnResolved(context.Background(), clientip.Result{Extraction: clientip.Extraction{Source: clientip.SourceRemoteAddr}})

	got := mustCounterValue(t, registry, "ip_resolution_total", map[string]string{
		"source": clientip.SourceRemoteAddr.String(),
		"result": clientip.ResultSuccess.String(),
	})
	if got != 2 {
		t.Fatalf("shared counter = %v, want 2", got)
	}
}

func TestNewWithRegisterer_TypedNilUsesDefaultRegisterer(t *testing.T) {
	registry := withIsolatedDefaultRegistry(t)

	var registerer *prom.Registry
	metrics, err := clientipprom.NewWithRegisterer(registerer)
	if err != nil {
		t.Fatalf("NewWithRegisterer() error = %v", err)
	}

	metrics.OnResolved(context.Background(), clientip.Result{Extraction: clientip.Extraction{Source: clientip.SourceRemoteAddr}})

	got := mustCounterValue(t, registry, "ip_resolution_total", map[string]string{
		"source": clientip.SourceRemoteAddr.String(),
		"result": clientip.ResultSuccess.String(),
	})
	if got != 1 {
		t.Fatalf("ip_resolution_total counter = %v, want 1", got)
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
func (r *failOnRegisterCall) Unregister(prom.Collector) bool { return false }

func TestNewWithRegisterer_RegisterFailure(t *testing.T) {
	baseErr := errors.New("register failed")
	registerer := &failOnRegisterCall{failAt: 1, err: baseErr}
	_, err := clientipprom.NewWithRegisterer(registerer)
	if !errors.Is(err, baseErr) {
		t.Fatalf("error = %v, want wrapped register error", err)
	}
	if !strings.Contains(err.Error(), "ip_resolution_total") {
		t.Fatalf("error = %q, want metric name", err.Error())
	}
}

func TestNewWithRegisterer_IncompatibleCollectorType(t *testing.T) {
	registry := prom.NewRegistry()
	gauge := prom.NewGaugeVec(
		prom.GaugeOpts{
			Name: "ip_resolution_total",
			Help: "Total number of client IP resolution attempts by source and result classification.",
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

func mustCounterValue(tb testing.TB, registry *prom.Registry, metricName string, labels map[string]string) float64 {
	tb.Helper()
	value, found, err := lookupCounterValue(registry, metricName, labels)
	if err != nil {
		tb.Fatalf("lookupCounterValue(%q, %v) error = %v", metricName, labels, err)
	}
	if !found {
		tb.Fatalf("counter %q with labels %v not found", metricName, labels)
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

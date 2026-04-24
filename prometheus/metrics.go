package prometheus

import (
	"errors"
	"fmt"
	"reflect"

	prom "github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics is a Prometheus-backed implementation of clientip.Metrics.
type PrometheusMetrics struct {
	extractionTotal *prom.CounterVec
	securityEvents  *prom.CounterVec
}

// New creates Prometheus-backed metrics and registers its collectors on
// prom.DefaultRegisterer.
func New() (*PrometheusMetrics, error) {
	return NewWithRegisterer(nil)
}

// NewWithRegisterer creates Prometheus-backed metrics and registers its
// collectors on the given registerer.
//
// If registerer is nil, prom.DefaultRegisterer is used. If the metrics are
// already registered, existing compatible collectors are reused.
func NewWithRegisterer(registerer prom.Registerer) (*PrometheusMetrics, error) {
	if isNilRegisterer(registerer) {
		registerer = prom.DefaultRegisterer
	}

	extractionTotalCollector := prom.NewCounterVec(
		prom.CounterOpts{
			Name: "ip_extraction_total",
			Help: "Total number of IP extraction attempts by source (forwarded, x-forwarded-for, x-real-ip, remote-addr) and result (success, invalid).",
		},
		[]string{"source", "result"},
	)
	securityEventsCollector := prom.NewCounterVec(
		prom.CounterOpts{
			Name: "ip_extraction_security_events_total",
			Help: "Security-related events during IP extraction, labeled by event.",
		},
		[]string{"event"},
	)

	extractionTotal, err := registerCounterVec(registerer, extractionTotalCollector, "ip_extraction_total")
	if err != nil {
		return nil, err
	}

	securityEvents, err := registerCounterVec(registerer, securityEventsCollector, "ip_extraction_security_events_total")
	if err != nil {
		return nil, err
	}

	return &PrometheusMetrics{
		extractionTotal: extractionTotal,
		securityEvents:  securityEvents,
	}, nil
}

func isNilRegisterer(registerer prom.Registerer) bool {
	if registerer == nil {
		return true
	}

	rv := reflect.ValueOf(registerer)
	switch rv.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return rv.IsNil()
	default:
		return false
	}
}

func registerCounterVec(registerer prom.Registerer, collector *prom.CounterVec, metricName string) (*prom.CounterVec, error) {
	if err := registerer.Register(collector); err != nil {
		var alreadyRegistered prom.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			existing, ok := alreadyRegistered.ExistingCollector.(*prom.CounterVec)
			if ok {
				return existing, nil
			}
			return nil, fmt.Errorf("metric %q already registered with incompatible collector type %T", metricName, alreadyRegistered.ExistingCollector)
		}

		return nil, fmt.Errorf("register metric %q: %w", metricName, err)
	}

	return collector, nil
}

// RecordExtractionSuccess increments ip_extraction_total with result="success"
// for the provided source.
func (m *PrometheusMetrics) RecordExtractionSuccess(source string) {
	m.extractionTotal.WithLabelValues(source, "success").Inc()
}

// RecordExtractionFailure increments ip_extraction_total with result="invalid"
// for the provided source.
func (m *PrometheusMetrics) RecordExtractionFailure(source string) {
	m.extractionTotal.WithLabelValues(source, "invalid").Inc()
}

// RecordSecurityEvent increments ip_extraction_security_events_total for the
// provided event label.
func (m *PrometheusMetrics) RecordSecurityEvent(event string) {
	m.securityEvents.WithLabelValues(event).Inc()
}

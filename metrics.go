package clientip

import (
	"errors"
	"fmt"

	"github.com/prometheus/client_golang/prometheus"
)

type Metrics interface {
	RecordExtractionSuccess(source string)
	RecordExtractionFailure(source string)
	RecordSecurityEvent(event string)
}

type noopMetrics struct{}

func (noopMetrics) RecordExtractionSuccess(string) {}

func (noopMetrics) RecordExtractionFailure(string) {}

func (noopMetrics) RecordSecurityEvent(string) {}

type PrometheusMetrics struct {
	extractionTotal *prometheus.CounterVec
	securityEvents  *prometheus.CounterVec
}

func WithPrometheusMetrics() Option {
	return func(c *Config) error {
		metrics, err := NewPrometheusMetrics()
		if err != nil {
			return err
		}
		c.metrics = metrics
		return nil
	}
}

func WithPrometheusMetricsRegisterer(registerer prometheus.Registerer) Option {
	return func(c *Config) error {
		metrics, err := NewPrometheusMetricsWithRegisterer(registerer)
		if err != nil {
			return err
		}
		c.metrics = metrics
		return nil
	}
}

func NewPrometheusMetrics() (*PrometheusMetrics, error) {
	return NewPrometheusMetricsWithRegisterer(prometheus.DefaultRegisterer)
}

func NewPrometheusMetricsWithRegisterer(registerer prometheus.Registerer) (*PrometheusMetrics, error) {
	if registerer == nil {
		registerer = prometheus.DefaultRegisterer
	}

	extractionTotalCollector := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ip_extraction_total",
			Help: "Total number of IP extraction attempts by source (x-forwarded-for, x-real-ip, remote-addr) and result (success, invalid).",
		},
		[]string{"source", "result"},
	)
	securityEventsCollector := prometheus.NewCounterVec(
		prometheus.CounterOpts{
			Name: "ip_extraction_security_events_total",
			Help: "Security-related events during IP extraction: untrusted_proxy, multiple_headers, no_trusted_proxies, invalid_ip, private_ip, chain_too_long, proxy_count_out_of_range.",
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

func registerCounterVec(registerer prometheus.Registerer, collector *prometheus.CounterVec, metricName string) (*prometheus.CounterVec, error) {
	if err := registerer.Register(collector); err != nil {
		var alreadyRegistered prometheus.AlreadyRegisteredError
		if errors.As(err, &alreadyRegistered) {
			existing, ok := alreadyRegistered.ExistingCollector.(*prometheus.CounterVec)
			if ok {
				return existing, nil
			}
			return nil, fmt.Errorf("metric %q already registered with incompatible collector type %T", metricName, alreadyRegistered.ExistingCollector)
		}

		return nil, fmt.Errorf("register metric %q: %w", metricName, err)
	}

	return collector, nil
}

func (m *PrometheusMetrics) RecordExtractionSuccess(source string) {
	m.extractionTotal.WithLabelValues(source, "success").Inc()
}

func (m *PrometheusMetrics) RecordExtractionFailure(source string) {
	m.extractionTotal.WithLabelValues(source, "invalid").Inc()
}

func (m *PrometheusMetrics) RecordSecurityEvent(event string) {
	m.securityEvents.WithLabelValues(event).Inc()
}

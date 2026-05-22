package prometheus

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"github.com/abczzz13/clientip"
	prom "github.com/prometheus/client_golang/prometheus"
)

// Observer is a Prometheus-backed implementation of clientip.Observer.
//
// It exports ip_resolution_total{source,result} counters.
type Observer struct {
	resolutionTotal *prom.CounterVec
}

// New creates Prometheus-backed metrics and registers its collectors on
// prom.DefaultRegisterer.
//
// If compatible collectors with the same names are already registered, they
// are reused.
func New() (*Observer, error) {
	return NewWithRegisterer(nil)
}

// NewWithRegisterer creates Prometheus-backed metrics and registers its
// collectors on the given registerer.
//
// If registerer is nil, prom.DefaultRegisterer is used. If the metrics are
// already registered, existing compatible collectors are reused.
func NewWithRegisterer(registerer prom.Registerer) (*Observer, error) {
	if isNilRegisterer(registerer) {
		registerer = prom.DefaultRegisterer
	}

	resolutionTotalCollector := prom.NewCounterVec(
		prom.CounterOpts{
			Name: "ip_resolution_total",
			Help: "Total number of client IP resolution attempts by source and result classification.",
		},
		[]string{"source", "result"},
	)
	resolutionTotal, err := registerCounterVec(registerer, resolutionTotalCollector, "ip_resolution_total")
	if err != nil {
		return nil, err
	}

	return &Observer{
		resolutionTotal: resolutionTotal,
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

// OnResolved records one resolver result.
//
// The nil receiver guard allows callers to pass a typed-nil *Observer through
// WithObserver without panicking; the resolver's interface-nil check does not
// catch typed nils.
func (m *Observer) OnResolved(_ context.Context, result clientip.Result) {
	if m == nil {
		return
	}
	source := result.Source.String()
	if source == "" {
		source = "unknown"
	}
	m.resolutionTotal.WithLabelValues(source, result.Classify().String()).Inc()
}

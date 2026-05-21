// Package prometheus provides a Prometheus adapter for
// github.com/abczzz13/clientip.
//
// The package exposes constructors for a Prometheus-backed clientip.Metrics
// implementation, using either the default registerer or a caller-provided
// registerer.
//
// Metrics are exported as ip_extraction_total{source,result} and
// ip_extraction_security_events_total{event} counters.
package prometheus

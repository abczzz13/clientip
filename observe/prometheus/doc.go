// Package prometheus provides a Prometheus adapter for
// github.com/abczzz13/clientip.
//
// The package exposes constructors for a Prometheus-backed clientip.Observer
// implementation, using either the default registerer or a caller-provided
// registerer.
//
// Counters are exported as ip_resolution_total{source,result}.
package prometheus

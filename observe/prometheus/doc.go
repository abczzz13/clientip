// Package prometheus provides a Prometheus adapter for
// github.com/abczzz13/clientip.
//
// The package exposes constructors for a Prometheus-backed clientip.Observer
// implementation, using either the default registerer or a caller-provided
// registerer.
//
// Counters are exported as ip_resolution_total{source,result}. The source label
// is Result.Source.String(), or "unknown" when no source is available. The
// result label is Result.Classify().String(), producing low-cardinality values
// such as "success", "untrusted", "malformed", and "fallback".
//
// This adapter is intentionally a separate module so the root clientip package
// does not depend on Prometheus.
package prometheus

package clientip

// Metrics records extraction outcomes and security events emitted by
// Extractor.
//
// Implementations should be safe for concurrent use, as a single Extractor
// instance is typically shared across many goroutines.
type Metrics interface {
	// RecordExtractionSuccess is called when a source successfully returns a
	// client IP.
	RecordExtractionSuccess(source string)
	// RecordExtractionFailure is called when a source is attempted but cannot
	// return a valid client IP.
	RecordExtractionFailure(source string)
	// RecordSecurityEvent is called when the extractor observes a
	// security-relevant condition.
	RecordSecurityEvent(event string)
}

// noopMetrics is the default Metrics implementation when metrics are not
// explicitly configured.
type noopMetrics struct{}

func (noopMetrics) RecordExtractionSuccess(string) {}

func (noopMetrics) RecordExtractionFailure(string) {}

func (noopMetrics) RecordSecurityEvent(string) {}

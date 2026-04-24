package clientip

import "context"

// HeaderValues provides access to request header values by name.
//
// Implementations should return one slice entry per received header line.
// Single-IP sources rely on per-line values to detect duplicates, and chain
// sources preserve wire order across repeated lines.
//
// Header names are requested in canonical MIME format (for example
// "X-Forwarded-For").
//
// net/http's http.Header satisfies this interface directly.
type HeaderValues interface {
	Values(name string) []string
}

// HeaderValuesFunc adapts a function to the HeaderValues interface.
type HeaderValuesFunc func(name string) []string

// Values implements HeaderValues.
func (f HeaderValuesFunc) Values(name string) []string {
	if f == nil {
		return nil
	}

	return f(name)
}

// Input provides framework-agnostic request data for extraction.
//
// Context defaults to context.Background() when nil.
//
// For Headers, preserve repeated header lines as separate values for each
// header name (for example two X-Forwarded-For lines should yield a slice with
// length 2, and two X-Real-IP lines should also yield length 2).
type Input struct {
	Context    context.Context
	RemoteAddr string
	Path       string
	Headers    HeaderValues
}

func requestInputContext(input Input) context.Context {
	if input.Context == nil {
		return context.Background()
	}

	return input.Context
}

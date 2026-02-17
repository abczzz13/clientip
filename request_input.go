package clientip

import (
	"context"
	"net/http"
	"net/textproto"
	"net/url"
)

// HeaderValues provides access to request header values by name.
//
// Implementations should return one slice entry per received header line to
// preserve duplicate-header detection behavior.
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

// RequestInput provides framework-agnostic request data for extraction.
//
// Context defaults to context.Background() when nil.
//
// For Headers, preserve duplicate header lines as separate values for each
// header name (for example two X-Forwarded-For lines should yield a slice with
// length 2).
type RequestInput struct {
	Context    context.Context
	RemoteAddr string
	Path       string
	Headers    HeaderValues
}

func requestInputContext(input RequestInput) context.Context {
	if input.Context == nil {
		return context.Background()
	}

	return input.Context
}

func requestFromInput(input RequestInput, sourceHeaderKeys []string) *http.Request {
	req := &http.Request{RemoteAddr: input.RemoteAddr}
	if input.Path != "" {
		req.URL = &url.URL{Path: input.Path}
	}

	if input.Headers == nil {
		return req
	}

	if h, ok := input.Headers.(http.Header); ok {
		req.Header = h
		return req
	}

	if h, ok := input.Headers.(*http.Header); ok && h != nil {
		req.Header = *h
		return req
	}

	if h, ok := input.Headers.(HeaderValuesFunc); ok {
		if h == nil {
			return req
		}

		input.Headers = h
	} else if isNilInterface(input.Headers) {
		return req
	}

	if len(sourceHeaderKeys) == 0 {
		return req
	}
	if len(sourceHeaderKeys) == 1 {
		key := sourceHeaderKeys[0]
		values := input.Headers.Values(key)
		if len(values) > 0 {
			req.Header = http.Header{key: values}
		}

		return req
	}

	var headers http.Header
	for _, key := range sourceHeaderKeys {
		values := input.Headers.Values(key)
		if len(values) == 0 {
			continue
		}
		if headers == nil {
			headers = make(http.Header, len(sourceHeaderKeys))
		}

		headers[key] = values
	}

	if headers != nil {
		req.Header = headers
	}

	return req
}

func sourceHeaderKeys(sourcePriority []string) []string {
	keys := make([]string, 0, len(sourcePriority))
	seen := make(map[string]struct{}, len(sourcePriority))

	for _, sourceName := range sourcePriority {
		key, ok := sourceHeaderKey(sourceName)
		if !ok {
			continue
		}

		if _, duplicate := seen[key]; duplicate {
			continue
		}

		seen[key] = struct{}{}
		keys = append(keys, key)
	}

	return keys
}

func sourceHeaderKey(sourceName string) (string, bool) {
	switch sourceName {
	case SourceForwarded:
		return "Forwarded", true
	case SourceXForwardedFor:
		return "X-Forwarded-For", true
	case SourceXRealIP:
		return "X-Real-IP", true
	case SourceRemoteAddr:
		return "", false
	default:
		return textproto.CanonicalMIMEHeaderKey(sourceName), true
	}
}

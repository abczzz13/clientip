package clientip

import (
	"errors"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"testing"
)

type extractionState struct {
	HasIP  bool
	IP     string
	Source string
}

type errorTextState struct {
	HasErr       bool
	ContainsText bool
}

func errorIsType(err error, target any) bool {
	if err == nil {
		return false
	}
	switch target.(type) {
	case *ExtractionError:
		var e *ExtractionError
		return asError(err, &e)
	case *MultipleHeadersError:
		var e *MultipleHeadersError
		return asError(err, &e)
	case *ProxyValidationError:
		var e *ProxyValidationError
		return asError(err, &e)
	case *InvalidIPError:
		var e *InvalidIPError
		return asError(err, &e)
	case *RemoteAddrError:
		var e *RemoteAddrError
		return asError(err, &e)
	default:
		return false
	}
}

func asError(err error, target any) bool {
	switch v := target.(type) {
	case **ExtractionError:
		return errors.As(err, v)
	case **MultipleHeadersError:
		return errors.As(err, v)
	case **ProxyValidationError:
		return errors.As(err, v)
	case **InvalidIPError:
		return errors.As(err, v)
	case **RemoteAddrError:
		return errors.As(err, v)
	default:
		return false
	}
}

func errorContains(err, target error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, target)
}

func extractionStateOf(extraction Extraction) extractionState {
	state := extractionState{
		HasIP:  extraction.IP.IsValid(),
		Source: extraction.Source,
	}

	if extraction.IP.IsValid() {
		state.IP = extraction.IP.String()
	}

	return state
}

func errorTextStateOf(err error, contains string) errorTextState {
	return errorTextState{
		HasErr:       err != nil,
		ContainsText: err != nil && strings.Contains(err.Error(), contains),
	}
}

func mustNewExtractor(t *testing.T, opts ...Option) *Extractor {
	t.Helper()

	extractor, err := New(opts...)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	return extractor
}

func mustParseCIDRs(t *testing.T, cidrs ...string) []netip.Prefix {
	t.Helper()

	prefixes, err := ParseCIDRs(cidrs...)
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	return prefixes
}

func newTestRequest(remoteAddr, path string) *http.Request {
	req := &http.Request{
		RemoteAddr: remoteAddr,
		Header:     make(http.Header),
	}

	if path != "" {
		req.URL = &url.URL{Path: path}
	}

	return req
}

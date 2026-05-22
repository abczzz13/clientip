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
	Source Source
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

func mustNewExtractor(t *testing.T, cfg options) *extractor {
	t.Helper()

	extractor, err := newExtractor(cfg)
	if err != nil {
		t.Fatalf("newExtractor() error = %v", err)
	}

	return extractor
}

// newResolverFromOptions builds a *Resolver from an internal options value.
// Tests use it when they want to assert on normalized config without round-
// tripping through the public functional-option API.
func newResolverFromOptions(opts options) (*Resolver, error) {
	extractor, err := newExtractor(opts)
	if err != nil {
		return nil, err
	}
	return &Resolver{extractor: extractor}, nil
}

func mustProxyPrefixesFromAddrs(t *testing.T, addrs ...netip.Addr) []netip.Prefix {
	t.Helper()

	prefixes, err := ProxyPrefixesFromAddrs(addrs...)
	if err != nil {
		t.Fatalf("ProxyPrefixesFromAddrs() error = %v", err)
	}

	return prefixes
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

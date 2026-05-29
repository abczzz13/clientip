package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/textproto"
	"testing"
)

func TestExtract_AllSourcesUnavailableReturnsLastSource(t *testing.T) {
	cfg := defaultOptions()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceXRealIP, HeaderSource("CF-Connecting-IP")}
	extractor := mustNewExtractor(t, cfg)

	req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}

	result, err := extractor.Extract(req)
	if !errors.Is(err, ErrSourceUnavailable) {
		t.Fatalf("error = %v, want ErrSourceUnavailable", err)
	}
	if got, want := result.Source, HeaderSource("CF-Connecting-IP"); got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
}

func TestExtract_UnknownSourceErrorIsTerminal(t *testing.T) {
	unexpectedErr := errors.New("unexpected extractor failure")
	extractor := &extractor{
		config: &config{sourceHeaderKeys: []string{"X-Forwarded-For"}},
		sources: []configuredSource{
			{
				source: SourceXForwardedFor,
				chain: chainExtractor{policy: chainPolicy{
					headerName: "X-Forwarded-For",
					parseValues: func([]string) ([]string, error) {
						return nil, unexpectedErr
					},
				}},
			},
			{
				source: SourceRemoteAddr,
				remote: remoteAddrExtractor{},
			},
		},
	}

	result, err := extractor.Extract(&http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header: http.Header{
			"X-Forwarded-For": {"1.1.1.1"},
		},
	})
	if !errors.Is(err, unexpectedErr) {
		t.Fatalf("error = %v, want %v", err, unexpectedErr)
	}
	if got, want := result.Source, SourceXForwardedFor; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
}

func TestExtractInput_ContextCanceledBeforeFallbackSource(t *testing.T) {
	cfg := defaultOptions()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{HeaderSource("CF-Connecting-IP"), SourceRemoteAddr}
	extractor := mustNewExtractor(t, cfg)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	requestedHeaders := make([]string, 0, 1)
	cfHeader := textproto.CanonicalMIMEHeaderKey("CF-Connecting-IP")
	_, err := extractor.ExtractInput(Input{
		Context:    ctx,
		RemoteAddr: "127.0.0.1:8080",
		Headers: HeaderValuesFunc(func(name string) []string {
			requestedHeaders = append(requestedHeaders, name)
			cancel()
			return nil
		}),
	})

	if !errors.Is(err, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", err)
	}
	if len(requestedHeaders) != 1 || requestedHeaders[0] != cfHeader {
		t.Fatalf("requested headers = %v, want [%q]", requestedHeaders, cfHeader)
	}
}

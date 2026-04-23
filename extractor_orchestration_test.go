package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/textproto"
	"testing"
)

func TestExtract_AllSourcesUnavailableReturnsLastSource(t *testing.T) {
	cfg := DefaultConfig()
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

func TestExtractInput_ContextCanceledBeforeFallbackSource(t *testing.T) {
	cfg := DefaultConfig()
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

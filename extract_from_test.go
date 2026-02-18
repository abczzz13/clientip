package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/textproto"
	"net/url"
	"testing"
)

type extractFromContextKey string

type panicOnNilHeaderProvider struct{}

func (p *panicOnNilHeaderProvider) Values(string) []string {
	if p == nil {
		panic("nil header provider should not be called")
	}

	return nil
}

func TestExtractFrom_ParityWithExtract(t *testing.T) {
	extractor, err := New(
		TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name    string
		headers []string
		remote  string
		wantErr error
	}{
		{
			name:   "remote_addr_only",
			remote: "8.8.8.8:8080",
		},
		{
			name:    "xff_success",
			remote:  "1.1.1.1:8080",
			headers: []string{"8.8.8.8"},
		},
		{
			name:    "duplicate_xff",
			remote:  "1.1.1.1:8080",
			headers: []string{"8.8.8.8", "9.9.9.9"},
			wantErr: ErrMultipleXFFHeaders,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.WithValue(context.Background(), extractFromContextKey("trace_id"), "trace-123")
			req := (&http.Request{
				RemoteAddr: tt.remote,
				Header:     make(http.Header),
				URL:        &url.URL{Path: "/parity"},
			}).WithContext(ctx)

			for _, value := range tt.headers {
				req.Header.Add("X-Forwarded-For", value)
			}

			httpExtraction, httpErr := extractor.Extract(req)

			inputExtraction, inputErr := extractor.ExtractFrom(RequestInput{
				Context:    req.Context(),
				RemoteAddr: req.RemoteAddr,
				Path:       req.URL.Path,
				Headers:    req.Header,
			})

			if tt.wantErr != nil {
				if !errors.Is(httpErr, tt.wantErr) {
					t.Fatalf("Extract() error = %v, want %v", httpErr, tt.wantErr)
				}
				if !errors.Is(inputErr, tt.wantErr) {
					t.Fatalf("ExtractFrom() error = %v, want %v", inputErr, tt.wantErr)
				}
				if inputExtraction.Source != httpExtraction.Source {
					t.Fatalf("source mismatch: ExtractFrom=%q Extract=%q", inputExtraction.Source, httpExtraction.Source)
				}
				return
			}

			if httpErr != nil {
				t.Fatalf("Extract() error = %v", httpErr)
			}
			if inputErr != nil {
				t.Fatalf("ExtractFrom() error = %v", inputErr)
			}

			if inputExtraction != httpExtraction {
				t.Fatalf("extraction mismatch: ExtractFrom=%+v Extract=%+v", inputExtraction, httpExtraction)
			}
		})
	}
}

func TestExtractFrom_HeaderValuesFunc(t *testing.T) {
	extractor, err := New(
		TrustLoopbackProxy(),
		Priority("CF-Connecting-IP", SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	cfHeader := textproto.CanonicalMIMEHeaderKey("CF-Connecting-IP")
	requestedHeaders := make([]string, 0, 1)
	headers := HeaderValuesFunc(func(name string) []string {
		requestedHeaders = append(requestedHeaders, name)
		if name == cfHeader {
			return []string{"9.9.9.9"}
		}
		return nil
	})

	extraction, err := extractor.ExtractFrom(RequestInput{
		RemoteAddr: "127.0.0.1:8080",
		Headers:    headers,
	})
	if err != nil {
		t.Fatalf("ExtractFrom() error = %v", err)
	}

	if got, want := extraction.Source, "cf_connecting_ip"; got != want {
		t.Fatalf("source = %q, want %q", got, want)
	}
	if got, want := extraction.IP, netip.MustParseAddr("9.9.9.9"); got != want {
		t.Fatalf("ip = %s, want %s", got, want)
	}
	if len(requestedHeaders) != 1 || requestedHeaders[0] != cfHeader {
		t.Fatalf("requested headers = %v, want [%q]", requestedHeaders, cfHeader)
	}
}

func TestExtractFrom_RemoteAddrOnlyDoesNotRequestHeaders(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	requested := 0
	input := RequestInput{
		RemoteAddr: "8.8.8.8:8080",
		Headers: HeaderValuesFunc(func(name string) []string {
			requested++
			return nil
		}),
	}

	extraction, err := extractor.ExtractFrom(input)
	if err != nil {
		t.Fatalf("ExtractFrom() error = %v", err)
	}
	if got, want := extraction.IP.String(), "8.8.8.8"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
	if requested != 0 {
		t.Fatalf("header provider called %d times, want 0", requested)
	}
}

func TestExtractFrom_TypedNilHeaderProviderTreatedAsAbsent(t *testing.T) {
	extractor, err := New(
		TrustProxyAddrs(netip.MustParseAddr("8.8.8.8")),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	var nilHTTPHeader *http.Header
	var nilProvider *panicOnNilHeaderProvider

	tests := []struct {
		name    string
		headers HeaderValues
	}{
		{name: "typed_nil_http_header_pointer", headers: nilHTTPHeader},
		{name: "typed_nil_custom_provider_pointer", headers: nilProvider},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extraction, extractErr := extractor.ExtractFrom(RequestInput{
				RemoteAddr: "8.8.8.8:8080",
				Headers:    tt.headers,
			})
			if extractErr != nil {
				t.Fatalf("ExtractFrom() error = %v", extractErr)
			}

			if got, want := extraction.Source, SourceRemoteAddr; got != want {
				t.Fatalf("source = %q, want %q", got, want)
			}
			if got, want := extraction.IP, netip.MustParseAddr("8.8.8.8"); got != want {
				t.Fatalf("ip = %s, want %s", got, want)
			}
		})
	}
}

func TestExtractFrom_RemoteAddrOnly_RespectsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	t.Run("default_remote_addr_priority", func(t *testing.T) {
		extractor, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		_, extractErr := extractor.ExtractFrom(RequestInput{
			Context:    ctx,
			RemoteAddr: "8.8.8.8:8080",
		})
		if !errors.Is(extractErr, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", extractErr)
		}
	})

	t.Run("override_to_remote_addr_priority", func(t *testing.T) {
		extractor, err := New(
			TrustProxyAddrs(netip.MustParseAddr("8.8.8.8")),
			Priority(SourceXForwardedFor, SourceRemoteAddr),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		_, extractErr := extractor.ExtractFrom(
			RequestInput{
				Context:    ctx,
				RemoteAddr: "8.8.8.8:8080",
			},
			OverrideOptions{SourcePriority: Set([]string{SourceRemoteAddr})},
		)
		if !errors.Is(extractErr, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", extractErr)
		}
	})
}

func TestExtractFrom_CanceledContext_DoesNotRequestHeaders(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	extractor, err := New(
		TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		Priority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	requested := 0
	_, extractErr := extractor.ExtractFrom(RequestInput{
		Context:    ctx,
		RemoteAddr: "1.1.1.1:8080",
		Headers: HeaderValuesFunc(func(name string) []string {
			requested++
			return []string{"8.8.8.8"}
		}),
	})
	if !errors.Is(extractErr, context.Canceled) {
		t.Fatalf("error = %v, want context.Canceled", extractErr)
	}
	if requested != 0 {
		t.Fatalf("header provider called %d times, want 0", requested)
	}
}

func TestExtractFrom_UsesInputContextAndPathInLogs(t *testing.T) {
	logger := &capturedLogger{}

	extractor, err := New(
		WithLogger(logger),
		TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	ctx := context.WithValue(context.Background(), loggerTestContextKey("trace_id"), "trace-from-input")
	headers := HeaderValuesFunc(func(name string) []string {
		if name == "X-Forwarded-For" {
			return []string{"8.8.8.8", "9.9.9.9"}
		}
		return nil
	})

	result, err := extractor.ExtractFrom(RequestInput{
		Context:    ctx,
		RemoteAddr: "1.1.1.1:8080",
		Path:       "/from-input",
		Headers:    headers,
	})
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction failure for duplicate X-Forwarded-For headers")
	}
	if !errors.Is(err, ErrMultipleXFFHeaders) {
		t.Fatalf("error = %v, want ErrMultipleXFFHeaders", err)
	}

	entries := logger.snapshot()
	if len(entries) != 1 {
		t.Fatalf("logged entries = %d, want 1", len(entries))
	}

	entry := entries[0]
	if got := entry.ctx.Value(loggerTestContextKey("trace_id")); got != "trace-from-input" {
		t.Fatalf("trace context value = %v, want %q", got, "trace-from-input")
	}

	assertCommonSecurityWarningAttrs(
		t,
		entry.attrs,
		securityEventMultipleHeaders,
		SourceXForwardedFor,
		"/from-input",
		"1.1.1.1:8080",
	)
}

func TestExtractFrom_OneShotHelpersAndNilContext(t *testing.T) {
	input := RequestInput{RemoteAddr: "8.8.8.8:8080"}

	extraction, err := ExtractFromWithOptions(input)
	if err != nil {
		t.Fatalf("ExtractFromWithOptions() error = %v", err)
	}
	if got, want := extraction.IP.String(), "8.8.8.8"; got != want {
		t.Fatalf("IP = %q, want %q", got, want)
	}
	if got, want := extraction.Source, SourceRemoteAddr; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}

	addr, err := ExtractAddrFromWithOptions(input)
	if err != nil {
		t.Fatalf("ExtractAddrFromWithOptions() error = %v", err)
	}
	if got, want := addr.String(), "8.8.8.8"; got != want {
		t.Fatalf("IP = %q, want %q", got, want)
	}
}

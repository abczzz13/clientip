package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"net/textproto"
	"testing"

	"github.com/google/go-cmp/cmp"
)

type stubSourceExtractor struct {
	name   string
	result extractionResult
	err    error
	calls  *int
}

func (s *stubSourceExtractor) Extract(context.Context, *http.Request) (extractionResult, error) {
	if s.calls != nil {
		*s.calls = *s.calls + 1
	}

	return s.result, s.err
}

func (s *stubSourceExtractor) Name() string {
	return s.name
}

func TestChainedSource_Extract(t *testing.T) {
	extractor := mustNewExtractor(t)

	tests := []struct {
		name       string
		sources    []sourceExtractor
		remoteAddr string
		xff        string
		xRealIP    string
		wantValid  bool
		wantIP     string
		wantSource string
	}{
		{
			name: "first source succeeds",
			sources: []sourceExtractor{
				&forwardedForSource{extractor: extractor},
				&remoteAddrSource{extractor: extractor},
			},
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1",
			wantValid:  true,
			wantIP:     "1.1.1.1",
			wantSource: SourceXForwardedFor,
		},
		{
			name: "fallback to second source",
			sources: []sourceExtractor{
				&forwardedForSource{extractor: extractor},
				&remoteAddrSource{extractor: extractor},
			},
			remoteAddr: "1.1.1.1:8080",
			xff:        "",
			wantValid:  true,
			wantIP:     "1.1.1.1",
			wantSource: SourceRemoteAddr,
		},
		{
			name: "all sources fail",
			sources: []sourceExtractor{
				&forwardedForSource{extractor: extractor},
				&remoteAddrSource{extractor: extractor},
			},
			remoteAddr: "127.0.0.1:8080",
			xff:        "",
			wantValid:  false,
		},
		{
			name: "custom priority order",
			sources: []sourceExtractor{
				&singleHeaderSource{
					extractor:  extractor,
					headerName: "X-Real-IP",
					headerKey:  textproto.CanonicalMIMEHeaderKey("X-Real-IP"),
					sourceName: SourceXRealIP,
				},
				&forwardedForSource{extractor: extractor},
				&remoteAddrSource{extractor: extractor},
			},
			remoteAddr: "127.0.0.1:8080",
			xff:        "8.8.8.8",
			xRealIP:    "1.1.1.1",
			wantValid:  true,
			wantIP:     "1.1.1.1",
			wantSource: SourceXRealIP,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			chained := newChainedSource(extractor, tt.sources...)

			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}

			result, err := chained.Extract(context.Background(), req)

			if tt.wantValid {
				if err != nil {
					t.Errorf("Extract() error = %v, want nil", err)
				}
				want := netip.MustParseAddr(tt.wantIP)
				if result.IP != want {
					t.Errorf("Extract() IP = %v, want %v", result.IP, want)
				}

				if result.Source != tt.wantSource {
					t.Errorf("result.Source = %q, want %q", result.Source, tt.wantSource)
				}
			} else {
				if err == nil {
					t.Errorf("Extract() error = nil, want non-nil")
				}
			}
		})
	}
}

func TestChainedSource_ContextCanceledPrecheck(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name string
		ctx  func() context.Context
		want struct {
			Calls       int
			ErrCanceled bool
			IP          string
			Source      string
		}
	}{
		{
			name: "already canceled context does not call sources",
			ctx: func() context.Context {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return ctx
			},
			want: struct {
				Calls       int
				ErrCanceled bool
				IP          string
				Source      string
			}{Calls: 0, ErrCanceled: true},
		},
		{
			name: "active context calls first source",
			ctx: func() context.Context {
				return context.Background()
			},
			want: struct {
				Calls       int
				ErrCanceled bool
				IP          string
				Source      string
			}{Calls: 1, ErrCanceled: false, IP: "1.1.1.1", Source: "stub_source"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			source := &stubSourceExtractor{
				name:   "stub_source",
				result: extractionResult{IP: netip.MustParseAddr("1.1.1.1"), Source: "stub_source"},
				calls:  &calls,
			}
			chained := newChainedSource(extractor, source)

			result, extractErr := chained.Extract(tt.ctx(), &http.Request{Header: make(http.Header)})

			got := struct {
				Calls       int
				ErrCanceled bool
				IP          string
				Source      string
			}{
				Calls:       calls,
				ErrCanceled: errors.Is(extractErr, context.Canceled),
				Source:      result.Source,
			}
			if result.IP.IsValid() {
				got.IP = result.IP.String()
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("chained result mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestChainedSource_FillsEmptySourceNameFromSource(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	calls := 0
	source := &stubSourceExtractor{
		name:   "custom_source",
		result: extractionResult{IP: netip.MustParseAddr("1.1.1.1")},
		calls:  &calls,
	}
	chained := newChainedSource(extractor, source)

	got, extractErr := chained.Extract(context.Background(), &http.Request{Header: make(http.Header)})
	if extractErr != nil {
		t.Fatalf("Extract() error = %v", extractErr)
	}

	gotView := struct {
		Calls  int
		IP     string
		Source string
	}{
		Calls:  calls,
		IP:     got.IP.String(),
		Source: got.Source,
	}
	wantView := struct {
		Calls  int
		IP     string
		Source string
	}{
		Calls:  1,
		IP:     "1.1.1.1",
		Source: "custom_source",
	}

	if diff := cmp.Diff(wantView, gotView); diff != "" {
		t.Fatalf("extraction mismatch (-want +got):\n%s", diff)
	}
}

func TestChainedSource_Name(t *testing.T) {
	extractor := mustNewExtractor(t)
	sources := []sourceExtractor{
		&forwardedForSource{extractor: extractor},
		&singleHeaderSource{
			extractor:  extractor,
			headerName: "X-Real-IP",
			headerKey:  textproto.CanonicalMIMEHeaderKey("X-Real-IP"),
			sourceName: SourceXRealIP,
		},
		&remoteAddrSource{extractor: extractor},
	}

	chained := newChainedSource(extractor, sources...)
	name := chained.Name()

	expectedName := "chained[x_forwarded_for,x_real_ip,remote_addr]"
	if name != expectedName {
		t.Errorf("Name() = %q, want %q", name, expectedName)
	}
}

func TestSourceFactories(t *testing.T) {
	extractor := mustNewExtractor(t)

	t.Run("Forwarded source", func(t *testing.T) {
		source := newForwardedSource(extractor)
		if source.Name() != SourceForwarded {
			t.Errorf("newForwardedSource() source name = %q, want %q", source.Name(), SourceForwarded)
		}
	})

	t.Run("XForwardedFor source", func(t *testing.T) {
		source := newForwardedForSource(extractor)
		if source.Name() != SourceXForwardedFor {
			t.Errorf("newForwardedForSource() source name = %q, want %q", source.Name(), SourceXForwardedFor)
		}
	})

	t.Run("XRealIP source", func(t *testing.T) {
		source := newSingleHeaderSource(extractor, "X-Real-IP")
		if source.Name() != SourceXRealIP {
			t.Errorf("newSingleHeaderSource(X-Real-IP) source name = %q, want %q", source.Name(), SourceXRealIP)
		}

		single, ok := source.(*singleHeaderSource)
		if !ok {
			t.Fatalf("newSingleHeaderSource() type = %T, want *singleHeaderSource", source)
		}

		wantHeaderKey := textproto.CanonicalMIMEHeaderKey("X-Real-IP")
		if single.headerKey != wantHeaderKey {
			t.Errorf("newSingleHeaderSource(X-Real-IP) headerKey = %q, want %q", single.headerKey, wantHeaderKey)
		}
	})

	t.Run("RemoteAddr source", func(t *testing.T) {
		source := newRemoteAddrSource(extractor)
		if source.Name() != SourceRemoteAddr {
			t.Errorf("newRemoteAddrSource() source name = %q, want %q", source.Name(), SourceRemoteAddr)
		}
	})

	t.Run("Custom header source", func(t *testing.T) {
		source := newSingleHeaderSource(extractor, "X-Custom-Header")
		if source.Name() != "x_custom_header" {
			t.Errorf("newSingleHeaderSource() source name = %q, want %q", source.Name(), "x_custom_header")
		}
	})
}

func TestNormalizeSourceName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{
			input: "X-Forwarded-For",
			want:  "x_forwarded_for",
		},
		{
			input: "Forwarded",
			want:  "forwarded",
		},
		{
			input: "X-Real-IP",
			want:  "x_real_ip",
		},
		{
			input: "CF-Connecting-IP",
			want:  "cf_connecting_ip",
		},
		{
			input: "UPPERCASE-HEADER",
			want:  "uppercase_header",
		},
		{
			input: "already_underscored",
			want:  "already_underscored",
		},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := NormalizeSourceName(tt.input)
			if got != tt.want {
				t.Errorf("NormalizeSourceName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestSourceUnavailableErrors(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	t.Run("forwarded_for_missing", func(t *testing.T) {
		source := &forwardedForSource{extractor: extractor}
		req := &http.Request{Header: make(http.Header)}

		_, extractErr := source.Extract(context.Background(), req)
		if !errors.Is(extractErr, ErrSourceUnavailable) {
			t.Fatalf("error = %v, want ErrSourceUnavailable", extractErr)
		}
	})

	t.Run("forwarded_missing", func(t *testing.T) {
		source := &forwardedSource{extractor: extractor}
		req := &http.Request{Header: make(http.Header)}

		_, extractErr := source.Extract(context.Background(), req)
		if !errors.Is(extractErr, ErrSourceUnavailable) {
			t.Fatalf("error = %v, want ErrSourceUnavailable", extractErr)
		}
	})

	t.Run("single_header_missing", func(t *testing.T) {
		source := &singleHeaderSource{
			extractor:  extractor,
			headerName: "X-Real-IP",
			headerKey:  textproto.CanonicalMIMEHeaderKey("X-Real-IP"),
			sourceName: SourceXRealIP,
		}
		req := &http.Request{Header: make(http.Header)}

		_, extractErr := source.Extract(context.Background(), req)
		if !errors.Is(extractErr, ErrSourceUnavailable) {
			t.Fatalf("error = %v, want ErrSourceUnavailable", extractErr)
		}
	})

	t.Run("remote_addr_missing", func(t *testing.T) {
		source := &remoteAddrSource{extractor: extractor}
		req := &http.Request{Header: make(http.Header)}

		_, extractErr := source.Extract(context.Background(), req)
		if !errors.Is(extractErr, ErrSourceUnavailable) {
			t.Fatalf("error = %v, want ErrSourceUnavailable", extractErr)
		}
	})
}

package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

func TestChainedSource_Extract(t *testing.T) {
	extractor, _ := New()

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

func TestChainedSource_Name(t *testing.T) {
	extractor, _ := New()
	sources := []sourceExtractor{
		&forwardedForSource{extractor: extractor},
		&singleHeaderSource{
			extractor:  extractor,
			headerName: "X-Real-IP",
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
	extractor, _ := New()

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

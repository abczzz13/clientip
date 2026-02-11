package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestForwardedForSource_Extract(t *testing.T) {
	extractor, _ := New()
	source := &forwardedForSource{extractor: extractor}

	tests := []struct {
		name        string
		xffHeaders  []string
		wantValid   bool
		wantIP      string
		wantErr     error
		wantErrType any
	}{
		{
			name:       "single valid IP",
			xffHeaders: []string{"1.1.1.1"},
			wantValid:  true,
			wantIP:     "1.1.1.1",
		},
		{
			name:       "multiple IPs in chain",
			xffHeaders: []string{"1.1.1.1, 8.8.8.8"},
			wantValid:  true,
			wantIP:     "1.1.1.1",
		},
		{
			name:        "no XFF header",
			xffHeaders:  []string{},
			wantValid:   false,
			wantErrType: &ExtractionError{},
		},
		{
			name:        "multiple XFF headers",
			xffHeaders:  []string{"1.1.1.1", "8.8.8.8"},
			wantValid:   false,
			wantErr:     ErrMultipleXFFHeaders,
			wantErrType: &MultipleHeadersError{},
		},
		{
			name:       "invalid IP in chain",
			xffHeaders: []string{"not-an-ip"},
			wantValid:  false,
		},
		{
			name:       "private IP rejected",
			xffHeaders: []string{"192.168.1.1"},
			wantValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: make(http.Header),
			}
			for _, h := range tt.xffHeaders {
				req.Header.Add("X-Forwarded-For", h)
			}

			result, err := source.Extract(context.Background(), req)

			if tt.wantValid {
				if err != nil {
					t.Errorf("Extract() error = %v, want nil", err)
				}
				want := netip.MustParseAddr(tt.wantIP)
				if result.IP != want {
					t.Errorf("Extract() IP = %v, want %v", result.IP, want)
				}
			} else {
				if err == nil {
					t.Errorf("Extract() error = nil, want non-nil")
				}
			}

			if tt.wantErrType != nil {
				if !errorIsType(err, tt.wantErrType) {
					t.Errorf("Extract() error type = %T, want %T", err, tt.wantErrType)
				}
			}

			if tt.wantErr != nil {
				if !errorContains(err, tt.wantErr) {
					t.Errorf("Extract() error does not contain expected error: %v", tt.wantErr)
				}
			}
		})
	}
}

func TestForwardedForSource_Name(t *testing.T) {
	extractor, _ := New()
	source := &forwardedForSource{extractor: extractor}

	if source.Name() != SourceXForwardedFor {
		t.Errorf("Name() = %q, want %q", source.Name(), SourceXForwardedFor)
	}
}

func TestForwardedSource_Extract(t *testing.T) {
	extractor, _ := New()
	source := &forwardedSource{extractor: extractor}

	tests := []struct {
		name        string
		forwarded   []string
		wantValid   bool
		wantIP      string
		wantErr     error
		wantErrType any
	}{
		{
			name:      "single valid for value",
			forwarded: []string{"for=1.1.1.1"},
			wantValid: true,
			wantIP:    "1.1.1.1",
		},
		{
			name:      "quoted IPv6 with port",
			forwarded: []string{"for=\"[2606:4700:4700::1]:8080\""},
			wantValid: true,
			wantIP:    "2606:4700:4700::1",
		},
		{
			name:        "no Forwarded header",
			forwarded:   nil,
			wantValid:   false,
			wantErrType: &ExtractionError{},
		},
		{
			name:        "malformed Forwarded header",
			forwarded:   []string{"for=\"1.1.1.1"},
			wantValid:   false,
			wantErr:     ErrInvalidForwardedHeader,
			wantErrType: &ExtractionError{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				Header: make(http.Header),
			}
			for _, h := range tt.forwarded {
				req.Header.Add("Forwarded", h)
			}

			result, err := source.Extract(context.Background(), req)

			got := struct {
				Valid bool
				IP    string
			}{
				Valid: err == nil,
			}
			if err == nil {
				got.IP = result.IP.String()
			}

			want := struct {
				Valid bool
				IP    string
			}{
				Valid: tt.wantValid,
			}
			if tt.wantValid {
				want.IP = netip.MustParseAddr(tt.wantIP).String()
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}

			if tt.wantErrType != nil {
				if !errorIsType(err, tt.wantErrType) {
					t.Errorf("Extract() error type = %T, want %T", err, tt.wantErrType)
				}
			}

			if tt.wantErr != nil {
				if !errorContains(err, tt.wantErr) {
					t.Errorf("Extract() error does not contain expected error: %v", tt.wantErr)
				}
			}
		})
	}
}

func TestForwardedSource_Name(t *testing.T) {
	extractor, _ := New()
	source := &forwardedSource{extractor: extractor}

	if source.Name() != SourceForwarded {
		t.Errorf("Name() = %q, want %q", source.Name(), SourceForwarded)
	}
}

func TestSingleHeaderSource_Extract(t *testing.T) {
	extractor, _ := New()

	tests := []struct {
		name        string
		headerName  string
		headerValue string
		wantValid   bool
		wantIP      string
	}{
		{
			name:        "valid IP",
			headerName:  "X-Real-IP",
			headerValue: "1.1.1.1",
			wantValid:   true,
			wantIP:      "1.1.1.1",
		},
		{
			name:        "IPv6",
			headerName:  "X-Real-IP",
			headerValue: "2606:4700:4700::1",
			wantValid:   true,
			wantIP:      "2606:4700:4700::1",
		},
		{
			name:        "empty header",
			headerName:  "X-Real-IP",
			headerValue: "",
			wantValid:   false,
		},
		{
			name:        "invalid IP",
			headerName:  "X-Real-IP",
			headerValue: "not-an-ip",
			wantValid:   false,
		},
		{
			name:        "private IP rejected",
			headerName:  "X-Real-IP",
			headerValue: "192.168.1.1",
			wantValid:   false,
		},
		{
			name:        "custom header name",
			headerName:  "CF-Connecting-IP",
			headerValue: "1.1.1.1",
			wantValid:   true,
			wantIP:      "1.1.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			source := &singleHeaderSource{
				extractor:  extractor,
				headerName: tt.headerName,
				sourceName: NormalizeSourceName(tt.headerName),
			}

			req := &http.Request{
				Header: make(http.Header),
			}
			if tt.headerValue != "" {
				req.Header.Set(tt.headerName, tt.headerValue)
			}

			result, err := source.Extract(context.Background(), req)

			if tt.wantValid {
				if err != nil {
					t.Errorf("Extract() error = %v, want nil", err)
				}
				want := netip.MustParseAddr(tt.wantIP)
				if result.IP != want {
					t.Errorf("Extract() IP = %v, want %v", result.IP, want)
				}
			} else {
				if err == nil {
					t.Errorf("Extract() error = nil, want non-nil")
				}
			}
		})
	}
}

func TestSingleHeaderSource_Extract_MultipleHeaderValues(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	source := &singleHeaderSource{
		extractor:  extractor,
		headerName: "X-Real-IP",
		sourceName: NormalizeSourceName("X-Real-IP"),
	}

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Real-IP", "1.1.1.1")
	req.Header.Add("X-Real-IP", "8.8.8.8")

	_, extractErr := source.Extract(context.Background(), req)
	if extractErr == nil {
		t.Fatal("Extract() error = nil, want error")
	}

	if !errors.Is(extractErr, ErrMultipleSingleIPHeaders) {
		t.Fatalf("error = %v, want ErrMultipleSingleIPHeaders", extractErr)
	}

	var multipleHeadersErr *MultipleHeadersError
	if !errors.As(extractErr, &multipleHeadersErr) {
		t.Fatalf("error type = %T, want *MultipleHeadersError", extractErr)
	}

	if multipleHeadersErr.HeaderCount != 2 {
		t.Fatalf("HeaderCount = %d, want 2", multipleHeadersErr.HeaderCount)
	}

	if multipleHeadersErr.HeaderName != "X-Real-IP" {
		t.Fatalf("HeaderName = %q, want %q", multipleHeadersErr.HeaderName, "X-Real-IP")
	}
}

func TestSingleHeaderSource_Name(t *testing.T) {
	extractor, _ := New()

	tests := []struct {
		headerName string
		wantName   string
	}{
		{
			headerName: "X-Real-IP",
			wantName:   "x_real_ip",
		},
		{
			headerName: "CF-Connecting-IP",
			wantName:   "cf_connecting_ip",
		},
		{
			headerName: "X-Custom-Header",
			wantName:   "x_custom_header",
		},
	}

	for _, tt := range tests {
		t.Run(tt.headerName, func(t *testing.T) {
			source := &singleHeaderSource{
				extractor:  extractor,
				headerName: tt.headerName,
				sourceName: NormalizeSourceName(tt.headerName),
			}

			if source.Name() != tt.wantName {
				t.Errorf("Name() = %q, want %q", source.Name(), tt.wantName)
			}
		})
	}
}

func TestRemoteAddrSource_Extract(t *testing.T) {
	extractor, _ := New()
	source := &remoteAddrSource{extractor: extractor}

	tests := []struct {
		name       string
		remoteAddr string
		wantValid  bool
		wantIP     string
	}{
		{
			name:       "valid IPv4 with port",
			remoteAddr: "1.1.1.1:12345",
			wantValid:  true,
			wantIP:     "1.1.1.1",
		},
		{
			name:       "valid IPv6 with port",
			remoteAddr: "[2606:4700:4700::1]:8080",
			wantValid:  true,
			wantIP:     "2606:4700:4700::1",
		},
		{
			name:       "empty RemoteAddr",
			remoteAddr: "",
			wantValid:  false,
		},
		{
			name:       "loopback rejected",
			remoteAddr: "127.0.0.1:8080",
			wantValid:  false,
		},
		{
			name:       "private IP rejected",
			remoteAddr: "192.168.1.1:8080",
			wantValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
			}

			result, err := source.Extract(context.Background(), req)

			if tt.wantValid {
				if err != nil {
					t.Errorf("Extract() error = %v, want nil", err)
				}
				want := netip.MustParseAddr(tt.wantIP)
				if result.IP != want {
					t.Errorf("Extract() IP = %v, want %v", result.IP, want)
				}
			} else {
				if err == nil {
					t.Errorf("Extract() error = nil, want non-nil")
				}
			}
		})
	}
}

func TestRemoteAddrSource_Name(t *testing.T) {
	extractor, _ := New()
	source := &remoteAddrSource{extractor: extractor}

	if source.Name() != SourceRemoteAddr {
		t.Errorf("Name() = %q, want %q", source.Name(), SourceRemoteAddr)
	}
}

func TestChainedSource_Extract(t *testing.T) {
	extractor, _ := New()

	tests := []struct {
		name       string
		sources    []Source
		remoteAddr string
		xff        string
		xRealIP    string
		wantValid  bool
		wantIP     string
		wantSource string
	}{
		{
			name: "first source succeeds",
			sources: []Source{
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
			sources: []Source{
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
			sources: []Source{
				&forwardedForSource{extractor: extractor},
				&remoteAddrSource{extractor: extractor},
			},
			remoteAddr: "127.0.0.1:8080",
			xff:        "",
			wantValid:  false,
		},
		{
			name: "custom priority order",
			sources: []Source{
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
	sources := []Source{
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

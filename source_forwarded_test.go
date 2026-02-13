package clientip

import (
	"context"
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

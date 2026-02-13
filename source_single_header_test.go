package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

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

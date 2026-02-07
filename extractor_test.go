package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"
)

func TestExtractIP_RemoteAddr(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		want       string
		wantValid  bool
		wantSource string
	}{
		{
			name:       "valid IPv4 with port",
			remoteAddr: "1.1.1.1:12345",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "valid IPv4 without port",
			remoteAddr: "1.1.1.1",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "valid IPv6 with port",
			remoteAddr: "[2606:4700:4700::1]:8080",
			want:       "2606:4700:4700::1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "valid IPv6 without port",
			remoteAddr: "2606:4700:4700::1",
			want:       "2606:4700:4700::1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "loopback rejected",
			remoteAddr: "127.0.0.1:8080",
			wantValid:  false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "IPv6 loopback rejected",
			remoteAddr: "[::1]:8080",
			wantValid:  false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "private IP rejected by default",
			remoteAddr: "192.168.1.1:8080",
			wantValid:  false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "link-local rejected",
			remoteAddr: "169.254.1.1:8080",
			wantValid:  false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "empty RemoteAddr",
			remoteAddr: "",
			wantValid:  false,
			wantSource: SourceRemoteAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}

			result := extractor.ExtractIP(req)

			if result.Valid() != tt.wantValid {
				t.Errorf("Valid() = %v, want %v (err: %v)", result.Valid(), tt.wantValid, result.Err)
			}

			if result.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", result.Source, tt.wantSource)
			}

			if tt.wantValid {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtractIP_XForwardedFor(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
		wantValid  bool
		wantSource string
	}{
		{
			name:       "single valid IP",
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "multiple IPs - leftmost selected",
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1, 8.8.8.8",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "IPv6 in XFF",
			remoteAddr: "127.0.0.1:8080",
			xff:        "2606:4700:4700::1",
			want:       "2606:4700:4700::1",
			wantValid:  true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "whitespace trimmed",
			remoteAddr: "127.0.0.1:8080",
			xff:        "  1.1.1.1  ,  8.8.8.8  ",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "invalid IP in XFF fallback to RemoteAddr",
			remoteAddr: "1.1.1.1:8080",
			xff:        "not-an-ip",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "private IP in XFF rejected",
			remoteAddr: "1.1.1.1:8080",
			xff:        "192.168.1.1",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			req.Header.Set("X-Forwarded-For", tt.xff)

			result := extractor.ExtractIP(req)

			if result.Valid() != tt.wantValid {
				t.Errorf("Valid() = %v, want %v (err: %v)", result.Valid(), tt.wantValid, result.Err)
			}

			if result.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", result.Source, tt.wantSource)
			}

			if tt.wantValid {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtractIP_StrictMode_TerminalSecurityErrors(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "9.9.9.9")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail closed on multiple XFF headers")
	}
	if !errors.Is(result.Err, ErrMultipleXFFHeaders) {
		t.Fatalf("error = %v, want ErrMultipleXFFHeaders", result.Err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
}

func TestExtractIP_SecurityModeLax_AllowsFallbackOnSecurityErrors(t *testing.T) {
	extractor, err := New(WithSecurityMode(SecurityModeLax))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "9.9.9.9")

	result := extractor.ExtractIP(req)
	if !result.Valid() {
		t.Fatalf("expected SecurityModeLax fallback success, got error: %v", result.Err)
	}
	if result.Source != SourceRemoteAddr {
		t.Fatalf("source = %q, want %q", result.Source, SourceRemoteAddr)
	}
	if got, want := result.IP.String(), "1.1.1.1"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtractIP_ChainTooLong_IsTerminalByDefault(t *testing.T) {
	extractor, err := New(MaxChainLength(2))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9, 4.4.4.4")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail on overlong XFF chain")
	}
	if !errors.Is(result.Err, ErrChainTooLong) {
		t.Fatalf("error = %v, want ErrChainTooLong", result.Err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
}

func TestExtractIP_StrictMode_UntrustedProxy_IsTerminal(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		TrustedProxies(cidrs, 1, 3),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		t.Fatal("expected extraction to fail on untrusted proxy in strict mode")
	}
	if !errors.Is(result.Err, ErrUntrustedProxy) {
		t.Fatalf("error = %v, want ErrUntrustedProxy", result.Err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
}

func TestExtractIP_SecurityModeLax_AllowsFallbackOnUntrustedProxy(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		TrustedProxies(cidrs, 1, 3),
		WithSecurityMode(SecurityModeLax),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result := extractor.ExtractIP(req)
	if !result.Valid() {
		t.Fatalf("expected SecurityModeLax fallback success, got error: %v", result.Err)
	}
	if result.Source != SourceRemoteAddr {
		t.Fatalf("source = %q, want %q", result.Source, SourceRemoteAddr)
	}
	if got, want := result.IP.String(), "8.8.8.8"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtractIP_XRealIP(t *testing.T) {
	extractor, err := New(
		Priority(
			SourceXRealIP,
			SourceXForwardedFor,
			SourceRemoteAddr,
		),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		xRealIP    string
		xff        string
		want       string
		wantValid  bool
		wantSource string
	}{
		{
			name:       "X-Real-IP takes priority",
			remoteAddr: "127.0.0.1:8080",
			xRealIP:    "1.1.1.1",
			xff:        "8.8.8.8",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceXRealIP,
		},
		{
			name:       "fallback to XFF when X-Real-IP invalid",
			remoteAddr: "127.0.0.1:8080",
			xRealIP:    "not-an-ip",
			xff:        "8.8.8.8",
			want:       "8.8.8.8",
			wantValid:  true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "fallback chain works",
			remoteAddr: "1.1.1.1:8080",
			xRealIP:    "",
			xff:        "",
			want:       "1.1.1.1",
			wantValid:  true,
			wantSource: SourceRemoteAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			if tt.xRealIP != "" {
				req.Header.Set("X-Real-IP", tt.xRealIP)
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			result := extractor.ExtractIP(req)

			if result.Valid() != tt.wantValid {
				t.Errorf("Valid() = %v, want %v (err: %v)", result.Valid(), tt.wantValid, result.Err)
			}

			if result.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", result.Source, tt.wantSource)
			}

			if tt.wantValid {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtractIP_WithTrustedProxies(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		TrustedProxies(cidrs, 1, 2),
		Priority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		want           string
		wantValid      bool
		wantProxyCount int
		wantErr        error
	}{
		{
			name:           "one trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xff:            "1.1.1.1, 10.0.0.1",
			want:           "1.1.1.1",
			wantValid:      true,
			wantProxyCount: 1,
		},
		{
			name:           "two trusted proxies",
			remoteAddr:     "10.0.0.2:8080",
			xff:            "1.1.1.1, 10.0.0.1, 10.0.0.2",
			want:           "1.1.1.1",
			wantValid:      true,
			wantProxyCount: 2,
		},
		{
			name:       "untrusted immediate proxy",
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1, 10.0.0.1",
			wantValid:  false,
			wantErr:    ErrUntrustedProxy,
		},
		{
			name:       "trusted remote but no trusted proxies in XFF chain",
			remoteAddr: "10.0.0.1:8080",
			xff:        "1.1.1.1",
			wantValid:  false,
			wantErr:    ErrNoTrustedProxies,
		},
		{
			name:       "too many trusted proxies",
			remoteAddr: "10.0.0.3:8080",
			xff:        "1.1.1.1, 10.0.0.1, 10.0.0.2, 10.0.0.3",
			wantValid:  false,
			wantErr:    ErrTooManyTrustedProxies,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			req.Header.Set("X-Forwarded-For", tt.xff)

			result := extractor.ExtractIP(req)

			if result.Valid() != tt.wantValid {
				t.Errorf("Valid() = %v, want %v (err: %v)", result.Valid(), tt.wantValid, result.Err)
			}

			if tt.wantValid {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
				if result.TrustedProxyCount != tt.wantProxyCount {
					t.Errorf("TrustedProxyCount = %d, want %d", result.TrustedProxyCount, tt.wantProxyCount)
				}
			}

			if tt.wantErr != nil {
				if !errors.Is(result.Err, tt.wantErr) {
					t.Errorf("error = %v, want %v", result.Err, tt.wantErr)
				}
			}
		})
	}
}

func TestExtractIP_AllowPrivateIPs(t *testing.T) {
	extractor, err := New(
		AllowPrivateIPs(true),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		want       string
		wantValid  bool
	}{
		{
			name:       "private IPv4 allowed",
			remoteAddr: "192.168.1.1:8080",
			want:       "192.168.1.1",
			wantValid:  true,
		},
		{
			name:       "private 10.x allowed",
			remoteAddr: "10.0.0.1:8080",
			want:       "10.0.0.1",
			wantValid:  true,
		},
		{
			name:       "private 172.16.x allowed",
			remoteAddr: "172.16.0.1:8080",
			want:       "172.16.0.1",
			wantValid:  true,
		},
		{
			name:       "loopback still rejected",
			remoteAddr: "127.0.0.1:8080",
			wantValid:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}

			result := extractor.ExtractIP(req)

			if result.Valid() != tt.wantValid {
				t.Errorf("Valid() = %v, want %v (err: %v)", result.Valid(), tt.wantValid, result.Err)
			}

			if tt.wantValid {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtractIP_WithDebugInfo(t *testing.T) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, err := New(
		TrustedProxies(cidrs, 1, 2),
		WithDebugInfo(true),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8, 10.0.0.1")

	result := extractor.ExtractIP(req)

	if !result.Valid() {
		t.Fatalf("ExtractIP() failed: %v", result.Err)
	}

	if result.DebugInfo == nil {
		t.Fatal("DebugInfo is nil, expected non-nil")
	}

	if len(result.DebugInfo.FullChain) != 3 {
		t.Errorf("FullChain length = %d, want 3", len(result.DebugInfo.FullChain))
	}

	if result.DebugInfo.ClientIndex != 1 {
		t.Errorf("ClientIndex = %d, want 1", result.DebugInfo.ClientIndex)
	}

	if len(result.DebugInfo.TrustedIndices) != 1 {
		t.Errorf("TrustedIndices length = %d, want 1", len(result.DebugInfo.TrustedIndices))
	}
}

func TestExtractIP_ErrorTypes(t *testing.T) {
	t.Run("MultipleHeadersError", func(t *testing.T) {
		extractor, _ := New(Priority(SourceXForwardedFor))
		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Add("X-Forwarded-For", "8.8.8.8")
		req.Header.Add("X-Forwarded-For", "1.1.1.1")

		result := extractor.ExtractIP(req)

		if result.Valid() {
			t.Error("Expected invalid result for multiple headers")
		}

		var multipleHeadersErr *MultipleHeadersError
		if !errors.As(result.Err, &multipleHeadersErr) {
			t.Errorf("Expected MultipleHeadersError, got %T", result.Err)
		} else {
			if multipleHeadersErr.HeaderCount != 2 {
				t.Errorf("HeaderCount = %d, want 2", multipleHeadersErr.HeaderCount)
			}
		}

		if !errors.Is(result.Err, ErrMultipleXFFHeaders) {
			t.Error("Expected error to wrap ErrMultipleXFFHeaders")
		}
	})

	t.Run("ProxyValidationError", func(t *testing.T) {
		cidrs, _ := ParseCIDRs("10.0.0.0/8")
		extractor, _ := New(
			TrustedProxies(cidrs, 2, 3),
			Priority(SourceXForwardedFor),
		)

		req := &http.Request{
			RemoteAddr: "10.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

		result := extractor.ExtractIP(req)
		if !errors.Is(result.Err, ErrTooFewTrustedProxies) {
			t.Errorf("Expected error to wrap ErrTooFewTrustedProxies, got %v", result.Err)
		}

		var proxyValidationErr *ProxyValidationError
		if !errors.As(result.Err, &proxyValidationErr) {
			t.Errorf("Expected ProxyValidationError, got %T", result.Err)
		} else {
			if proxyValidationErr.TrustedProxyCount != 1 {
				t.Errorf("TrustedProxyCount = %d, want 1", proxyValidationErr.TrustedProxyCount)
			}
			if proxyValidationErr.MinTrustedProxies != 2 {
				t.Errorf("MinTrustedProxies = %d, want 2", proxyValidationErr.MinTrustedProxies)
			}
		}
	})

	t.Run("InvalidIPError", func(t *testing.T) {
		extractor, _ := New(Priority(SourceXForwardedFor))
		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "192.168.1.1")

		result := extractor.ExtractIP(req)

		var invalidIPErr *InvalidIPError
		if !errors.As(result.Err, &invalidIPErr) {
			t.Errorf("Expected InvalidIPError, got %T", result.Err)
		}
	})
}

func TestExtractIP_IPv4MappedIPv6(t *testing.T) {
	extractor, _ := New()

	req := &http.Request{
		RemoteAddr: "[::ffff:1.1.1.1]:8080",
		Header:     make(http.Header),
	}

	result := extractor.ExtractIP(req)

	if !result.Valid() {
		t.Fatalf("ExtractIP() failed: %v", result.Err)
	}

	if !result.IP.Is4() {
		t.Errorf("Expected IPv4 address, got %v", result.IP)
	}

	want := netip.MustParseAddr("1.1.1.1")
	if result.IP != want {
		t.Errorf("IP = %v, want %v", result.IP, want)
	}
}

func TestExtractIP_Concurrent(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}

	const goroutines = 100
	done := make(chan bool, goroutines)
	errors := make(chan error, goroutines)

	for i := 0; i < goroutines; i++ {
		go func() {
			result := extractor.ExtractIP(req)
			if !result.Valid() {
				errors <- result.Err
			} else {
				want := netip.MustParseAddr("1.1.1.1")
				if result.IP != want {
					errors <- &ExtractionError{Err: ErrInvalidIP, Source: "test"}
				}
			}
			done <- true
		}()
	}

	for i := 0; i < goroutines; i++ {
		<-done
	}

	close(errors)
	for err := range errors {
		t.Errorf("Concurrent extraction error: %v", err)
	}
}

type contextKey string

func TestExtractIP_ContextPropagation(t *testing.T) {
	extractor, _ := New()

	ctx := context.WithValue(context.Background(), contextKey("test-key"), "test-value")
	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req = req.WithContext(ctx)

	result := extractor.ExtractIP(req)

	if !result.Valid() {
		t.Errorf("ExtractIP() failed: %v", result.Err)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

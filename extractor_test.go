package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExtract_RemoteAddr(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		want       string
		wantOK     bool
		wantSource Source
	}{
		{
			name:       "valid IPv4 with port",
			remoteAddr: "1.1.1.1:12345",
			want:       "1.1.1.1",
			wantOK:     true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "valid IPv4 without port",
			remoteAddr: "1.1.1.1",
			want:       "1.1.1.1",
			wantOK:     true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "valid IPv6 with port",
			remoteAddr: "[2606:4700:4700::1]:8080",
			want:       "2606:4700:4700::1",
			wantOK:     true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "valid IPv6 without port",
			remoteAddr: "2606:4700:4700::1",
			want:       "2606:4700:4700::1",
			wantOK:     true,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "loopback rejected",
			remoteAddr: "127.0.0.1:8080",
			wantOK:     false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "IPv6 loopback rejected",
			remoteAddr: "[::1]:8080",
			wantOK:     false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "private IP rejected by default",
			remoteAddr: "192.168.1.1:8080",
			wantOK:     false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "link-local rejected",
			remoteAddr: "169.254.1.1:8080",
			wantOK:     false,
			wantSource: SourceRemoteAddr,
		},
		{
			name:       "empty RemoteAddr",
			remoteAddr: "",
			wantOK:     false,
			wantSource: SourceRemoteAddr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}

			result, err := extractor.Extract(req)

			got := struct {
				OK     bool
				Source Source
				IP     string
			}{
				OK:     (err == nil && result.IP.IsValid()),
				Source: result.Source,
			}
			if err == nil && result.IP.IsValid() {
				got.IP = result.IP.String()
			}

			want := struct {
				OK     bool
				Source Source
				IP     string
			}{
				OK:     tt.wantOK,
				Source: tt.wantSource,
			}
			if tt.wantOK {
				want.IP = netip.MustParseAddr(tt.want).String()
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_WithSourcePriorityAlias_CanonicalizesBuiltIns(t *testing.T) {
	t.Run("Forwarded alias uses Forwarded parser", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(HeaderSource("Forwarded"), SourceRemoteAddr),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("Forwarded", "for=9.9.9.9")
		req.Header.Set("X-Forwarded-For", "8.8.8.8")

		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			t.Fatalf("expected valid extraction, got error: %v", err)
		}
		if result.Source != SourceForwarded {
			t.Fatalf("source = %q, want %q", result.Source, SourceForwarded)
		}
		if got, want := result.IP.String(), "9.9.9.9"; got != want {
			t.Fatalf("IP = %q, want %q", got, want)
		}
	})

	t.Run("X-Forwarded-For alias combines multiple header lines", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(HeaderSource("X-Forwarded-For"), SourceRemoteAddr),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Add("X-Forwarded-For", "8.8.8.8")
		req.Header.Add("X-Forwarded-For", "9.9.9.9")

		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			t.Fatalf("expected valid extraction, got error: %v", err)
		}
		if result.Source != SourceXForwardedFor {
			t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
		}
		if got, want := result.IP.String(), "9.9.9.9"; got != want {
			t.Fatalf("IP = %q, want %q", got, want)
		}
	})

	t.Run("Remote-Addr alias maps to RemoteAddr source", func(t *testing.T) {
		extractor, err := New(WithSourcePriority(HeaderSource("Remote-Addr")))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "8.8.8.8:8080",
			Header:     make(http.Header),
		}

		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			t.Fatalf("expected valid extraction, got error: %v", err)
		}
		if result.Source != SourceRemoteAddr {
			t.Fatalf("source = %q, want %q", result.Source, SourceRemoteAddr)
		}
		if got, want := result.IP.String(), "8.8.8.8"; got != want {
			t.Fatalf("IP = %q, want %q", got, want)
		}
	})

	t.Run("X_Real_IP alias maps to X-Real-IP source", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(HeaderSource("X_Real_IP"), SourceRemoteAddr),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("X-Real-IP", "7.7.7.7")

		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			t.Fatalf("expected valid extraction, got error: %v", err)
		}
		if result.Source != SourceXRealIP {
			t.Fatalf("source = %q, want %q", result.Source, SourceXRealIP)
		}
		if got, want := result.IP.String(), "7.7.7.7"; got != want {
			t.Fatalf("IP = %q, want %q", got, want)
		}
	})
}

func TestExtract_XForwardedFor(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		want       string
		wantOK     bool
		wantSource Source
	}{
		{
			name:       "single valid IP",
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1",
			want:       "1.1.1.1",
			wantOK:     true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "multiple IPs - rightmost untrusted selected",
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1, 8.8.8.8",
			want:       "8.8.8.8",
			wantOK:     true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "IPv6 in XFF",
			remoteAddr: "127.0.0.1:8080",
			xff:        "2606:4700:4700::1",
			want:       "2606:4700:4700::1",
			wantOK:     true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "whitespace trimmed",
			remoteAddr: "127.0.0.1:8080",
			xff:        "  1.1.1.1  ,  8.8.8.8  ",
			want:       "8.8.8.8",
			wantOK:     true,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "invalid IP in XFF is terminal in strict mode",
			remoteAddr: "1.1.1.1:8080",
			xff:        "not-an-ip",
			wantOK:     false,
			wantSource: SourceXForwardedFor,
		},
		{
			name:       "private IP in XFF is terminal in strict mode",
			remoteAddr: "1.1.1.1:8080",
			xff:        "192.168.1.1",
			wantOK:     false,
			wantSource: SourceXForwardedFor,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			req.Header.Set("X-Forwarded-For", tt.xff)

			result, err := extractor.Extract(req)

			if (err == nil && result.IP.IsValid()) != tt.wantOK {
				t.Errorf("OK() = %v, want %v (err: %v)", (err == nil && result.IP.IsValid()), tt.wantOK, err)
			}

			if result.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", result.Source, tt.wantSource)
			}

			if tt.wantOK {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtract_Forwarded(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithSourcePriority(SourceForwarded, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		forwarded  []string
		xff        string
		want       string
		wantOK     bool
		wantSource Source
	}{
		{
			name:       "single valid for value",
			remoteAddr: "127.0.0.1:8080",
			forwarded:  []string{"for=1.1.1.1"},
			want:       "1.1.1.1",
			wantOK:     true,
			wantSource: SourceForwarded,
		},
		{
			name:       "quoted IPv6 with port",
			remoteAddr: "127.0.0.1:8080",
			forwarded:  []string{"for=\"[2606:4700:4700::1]:443\""},
			want:       "2606:4700:4700::1",
			wantOK:     true,
			wantSource: SourceForwarded,
		},
		{
			name:       "multiple Forwarded headers are combined",
			remoteAddr: "127.0.0.1:8080",
			forwarded:  []string{"for=1.1.1.1", "for=8.8.8.8"},
			want:       "8.8.8.8",
			wantOK:     true,
			wantSource: SourceForwarded,
		},
		{
			name:       "Forwarded takes precedence over XFF",
			remoteAddr: "127.0.0.1:8080",
			forwarded:  []string{"for=9.9.9.9"},
			xff:        "1.1.1.1",
			want:       "9.9.9.9",
			wantOK:     true,
			wantSource: SourceForwarded,
		},
		{
			name:       "malformed Forwarded is terminal in strict mode",
			remoteAddr: "127.0.0.1:8080",
			forwarded:  []string{"for=\"1.1.1.1"},
			xff:        "8.8.8.8",
			wantOK:     false,
			wantSource: SourceForwarded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			for _, forwardedValue := range tt.forwarded {
				req.Header.Add("Forwarded", forwardedValue)
			}
			if tt.xff != "" {
				req.Header.Set("X-Forwarded-For", tt.xff)
			}

			result, err := extractor.Extract(req)

			if (err == nil && result.IP.IsValid()) != tt.wantOK {
				t.Errorf("OK() = %v, want %v (err: %v)", (err == nil && result.IP.IsValid()), tt.wantOK, err)
			}

			if result.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", result.Source, tt.wantSource)
			}

			if tt.wantOK {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtract_Forwarded_WithTrustedProxies(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithTrustedProxyPrefixes(cidrs...),
		WithMinTrustedProxies(1),
		WithMaxTrustedProxies(2),
		WithSourcePriority(SourceForwarded),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name           string
		remoteAddr     string
		forwarded      []string
		want           string
		wantOK         bool
		wantProxyCount int
		wantErr        error
	}{
		{
			name:           "one trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			forwarded:      []string{"for=1.1.1.1, for=10.0.0.1"},
			want:           "1.1.1.1",
			wantOK:         true,
			wantProxyCount: 1,
		},
		{
			name:       "untrusted immediate proxy",
			remoteAddr: "8.8.8.8:8080",
			forwarded:  []string{"for=1.1.1.1, for=10.0.0.1"},
			wantOK:     false,
			wantErr:    ErrUntrustedProxy,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}
			for _, forwardedValue := range tt.forwarded {
				req.Header.Add("Forwarded", forwardedValue)
			}

			result, err := extractor.Extract(req)

			got := struct {
				OK                bool
				Source            Source
				IP                string
				TrustedProxyCount int
			}{
				OK:                (err == nil && result.IP.IsValid()),
				Source:            result.Source,
				TrustedProxyCount: result.TrustedProxyCount,
			}
			if err == nil && result.IP.IsValid() {
				got.IP = result.IP.String()
			}

			want := struct {
				OK                bool
				Source            Source
				IP                string
				TrustedProxyCount int
			}{
				OK:                tt.wantOK,
				Source:            SourceForwarded,
				TrustedProxyCount: tt.wantProxyCount,
			}
			if tt.wantOK {
				want.IP = netip.MustParseAddr(tt.want).String()
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Errorf("Extract() mismatch (-want +got):\n%s", diff)
			}

			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestExtract_ParsesMultipleXFFHeaders_AcrossSecurityModes(t *testing.T) {
	tests := []struct {
		name            string
		securityMode    SecurityMode
		setSecurityMode bool
	}{
		{name: "strict_default"},
		{name: "lax", securityMode: SecurityModeLax, setSecurityMode: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			opts := []Option{
				WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
				WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
			}
			if tt.setSecurityMode {
				opts = append(opts, WithSecurityMode(tt.securityMode))
			}

			extractor, err := New(opts...)
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			req := &http.Request{
				RemoteAddr: "1.1.1.1:8080",
				Header:     make(http.Header),
			}
			req.Header.Add("X-Forwarded-For", "8.8.8.8")
			req.Header.Add("X-Forwarded-For", "9.9.9.9")

			result, err := extractor.Extract(req)
			if err != nil || !result.IP.IsValid() {
				t.Fatalf("expected extraction to succeed, got error: %v", err)
			}
			if result.Source != SourceXForwardedFor {
				t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
			}
			if got, want := result.IP.String(), "9.9.9.9"; got != want {
				t.Fatalf("ip = %q, want %q", got, want)
			}
		})
	}
}

func TestExtract_StrictMode_MalformedForwarded_IsTerminal(t *testing.T) {
	extractor, err := New(
		WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		WithSourcePriority(SourceForwarded, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", "for=\"1.1.1.1")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail closed on malformed Forwarded")
	}
	if !errors.Is(err, ErrInvalidForwardedHeader) {
		t.Fatalf("error = %v, want ErrInvalidForwardedHeader", err)
	}
	if result.Source != SourceForwarded {
		t.Fatalf("source = %q, want %q", result.Source, SourceForwarded)
	}
}

func TestExtract_SecurityModeLax_AllowsFallbackOnMalformedForwarded(t *testing.T) {
	extractor, err := New(
		WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		WithSourcePriority(SourceForwarded, SourceRemoteAddr),
		WithSecurityMode(SecurityModeLax),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", "for=\"1.1.1.1")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected SecurityModeLax fallback success, got error: %v", err)
	}
	if result.Source != SourceRemoteAddr {
		t.Fatalf("source = %q, want %q", result.Source, SourceRemoteAddr)
	}
	if got, want := result.IP.String(), "1.1.1.1"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtract_ChainTooLong_IsTerminalByDefault(t *testing.T) {
	extractor, err := New(
		WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
		WithMaxChainLength(2),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9, 4.4.4.4")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail on overlong XFF chain")
	}
	if !errors.Is(err, ErrChainTooLong) {
		t.Fatalf("error = %v, want ErrChainTooLong", err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
}

func TestExtract_StrictMode_UntrustedProxy_IsTerminal(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithTrustedProxyPrefixes(cidrs...),
		WithMinTrustedProxies(1),
		WithMaxTrustedProxies(3),
		WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "8.8.8.8:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected extraction to fail on untrusted proxy in strict mode")
	}
	if !errors.Is(err, ErrUntrustedProxy) {
		t.Fatalf("error = %v, want ErrUntrustedProxy", err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
}

func TestExtract_SecurityModeLax_AllowsFallbackOnUntrustedProxy(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithTrustedProxyPrefixes(cidrs...),
		WithMinTrustedProxies(1),
		WithMaxTrustedProxies(3),
		WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
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

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected SecurityModeLax fallback success, got error: %v", err)
	}
	if result.Source != SourceRemoteAddr {
		t.Fatalf("source = %q, want %q", result.Source, SourceRemoteAddr)
	}
	if got, want := result.IP.String(), "8.8.8.8"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtract_SingleHeader_UntrustedProxy_StrictVsLax(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	tests := []struct {
		name    string
		mode    SecurityMode
		wantErr error
		want    extractionState
	}{
		{
			name:    "strict mode fails closed",
			mode:    SecurityModeStrict,
			wantErr: ErrUntrustedProxy,
			want:    extractionState{HasIP: false, Source: SourceXRealIP},
		},
		{
			name: "lax mode falls back to remote addr",
			mode: SecurityModeLax,
			want: extractionState{HasIP: true, IP: "8.8.8.8", Source: SourceRemoteAddr},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, newErr := New(
				WithTrustedProxyPrefixes(cidrs...),
				WithSourcePriority(SourceXRealIP, SourceRemoteAddr),
				WithSecurityMode(tt.mode),
			)
			if newErr != nil {
				t.Fatalf("New() error = %v", newErr)
			}

			req := &http.Request{
				RemoteAddr: "8.8.8.8:8080",
				Header:     make(http.Header),
			}
			req.Header.Set("X-Real-IP", "1.1.1.1")

			got, extractErr := extractor.Extract(req)

			if tt.wantErr != nil {
				if !errors.Is(extractErr, tt.wantErr) {
					t.Fatalf("error = %v, want %v", extractErr, tt.wantErr)
				}
			} else if extractErr != nil {
				t.Fatalf("Extract() error = %v", extractErr)
			}

			gotView := extractionStateOf(got)

			if diff := cmp.Diff(tt.want, gotView); diff != "" {
				t.Fatalf("extraction mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_XRealIP(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		WithSourcePriority(
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
		wantOK     bool
		wantSource Source
	}{
		{
			name:       "X-Real-IP takes priority",
			remoteAddr: "127.0.0.1:8080",
			xRealIP:    "1.1.1.1",
			xff:        "8.8.8.8",
			want:       "1.1.1.1",
			wantOK:     true,
			wantSource: SourceXRealIP,
		},
		{
			name:       "invalid X-Real-IP is terminal in strict mode",
			remoteAddr: "127.0.0.1:8080",
			xRealIP:    "not-an-ip",
			xff:        "8.8.8.8",
			wantOK:     false,
			wantSource: SourceXRealIP,
		},
		{
			name:       "fallback chain works",
			remoteAddr: "1.1.1.1:8080",
			xRealIP:    "",
			xff:        "",
			want:       "1.1.1.1",
			wantOK:     true,
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

			result, err := extractor.Extract(req)

			if (err == nil && result.IP.IsValid()) != tt.wantOK {
				t.Errorf("OK() = %v, want %v (err: %v)", (err == nil && result.IP.IsValid()), tt.wantOK, err)
			}

			if result.Source != tt.wantSource {
				t.Errorf("Source = %q, want %q", result.Source, tt.wantSource)
			}

			if tt.wantOK {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtract_SecurityModeLax_AllowsFallbackOnInvalidPreferredSingleHeader(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithSourcePriority(SourceXRealIP, SourceXForwardedFor, SourceRemoteAddr),
		WithSecurityMode(SecurityModeLax),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Real-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected lax-mode fallback to succeed, got error: %v", err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
	if got, want := result.IP.String(), "8.8.8.8"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtract_StrictMode_DuplicatePreferredSingleHeader_IsTerminal(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithSourcePriority(SourceXRealIP, SourceXForwardedFor, SourceRemoteAddr),
		WithSecurityMode(SecurityModeStrict),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Real-IP", "9.9.9.9")
	req.Header.Add("X-Real-IP", "8.8.8.8")
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result, err := extractor.Extract(req)
	if err == nil && result.IP.IsValid() {
		t.Fatal("expected strict-mode extraction to fail on duplicate single-IP headers")
	}
	if !errors.Is(err, ErrMultipleSingleIPHeaders) {
		t.Fatalf("error = %v, want ErrMultipleSingleIPHeaders", err)
	}
	if result.Source != SourceXRealIP {
		t.Fatalf("source = %q, want %q", result.Source, SourceXRealIP)
	}
}

func TestExtract_SecurityModeLax_AllowsFallbackOnDuplicatePreferredSingleHeader(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithSourcePriority(SourceXRealIP, SourceXForwardedFor, SourceRemoteAddr),
		WithSecurityMode(SecurityModeLax),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "127.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Real-IP", "9.9.9.9")
	req.Header.Add("X-Real-IP", "8.8.8.8")
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected lax-mode fallback to succeed, got error: %v", err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
	if got, want := result.IP.String(), "1.1.1.1"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtract_WithTrustedProxies(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithTrustedProxyPrefixes(cidrs...),
		WithMinTrustedProxies(1),
		WithMaxTrustedProxies(2),
		WithSourcePriority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name           string
		remoteAddr     string
		xff            string
		want           string
		wantOK         bool
		wantProxyCount int
		wantErr        error
	}{
		{
			name:           "one trusted proxy",
			remoteAddr:     "10.0.0.1:8080",
			xff:            "1.1.1.1, 10.0.0.1",
			want:           "1.1.1.1",
			wantOK:         true,
			wantProxyCount: 1,
		},
		{
			name:           "two trusted proxies",
			remoteAddr:     "10.0.0.2:8080",
			xff:            "1.1.1.1, 10.0.0.1, 10.0.0.2",
			want:           "1.1.1.1",
			wantOK:         true,
			wantProxyCount: 2,
		},
		{
			name:       "untrusted immediate proxy",
			remoteAddr: "127.0.0.1:8080",
			xff:        "1.1.1.1, 10.0.0.1",
			wantOK:     false,
			wantErr:    ErrUntrustedProxy,
		},
		{
			name:       "trusted remote but no trusted proxies in XFF chain",
			remoteAddr: "10.0.0.1:8080",
			xff:        "1.1.1.1",
			wantOK:     false,
			wantErr:    ErrNoTrustedProxies,
		},
		{
			name:       "too many trusted proxies",
			remoteAddr: "10.0.0.3:8080",
			xff:        "1.1.1.1, 10.0.0.1, 10.0.0.2, 10.0.0.3",
			wantOK:     false,
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

			result, err := extractor.Extract(req)

			if (err == nil && result.IP.IsValid()) != tt.wantOK {
				t.Errorf("OK() = %v, want %v (err: %v)", (err == nil && result.IP.IsValid()), tt.wantOK, err)
			}

			if tt.wantOK {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
				if result.TrustedProxyCount != tt.wantProxyCount {
					t.Errorf("TrustedProxyCount = %d, want %d", result.TrustedProxyCount, tt.wantProxyCount)
				}
			}

			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Errorf("error = %v, want %v", err, tt.wantErr)
				}
			}
		})
	}
}

func TestExtract_WithTrustedProxies_MinZero_AllowsClientOnlyXFF(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor, err := New(
		WithTrustedProxyPrefixes(cidrs...),
		WithMinTrustedProxies(0),
		WithMaxTrustedProxies(2),
		WithSourcePriority(SourceXForwardedFor),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.0.1:8080",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result, err := extractor.Extract(req)
	if err != nil || !result.IP.IsValid() {
		t.Fatalf("expected extraction to succeed, got error: %v", err)
	}
	if result.Source != SourceXForwardedFor {
		t.Fatalf("source = %q, want %q", result.Source, SourceXForwardedFor)
	}
	if result.TrustedProxyCount != 0 {
		t.Fatalf("TrustedProxyCount = %d, want 0", result.TrustedProxyCount)
	}
	if got, want := result.IP.String(), "1.1.1.1"; got != want {
		t.Fatalf("ip = %q, want %q", got, want)
	}
}

func TestExtract_WithAllowPrivateIPs(t *testing.T) {
	extractor, err := New(
		WithAllowPrivateIPs(true),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	tests := []struct {
		name       string
		remoteAddr string
		want       string
		wantOK     bool
	}{
		{
			name:       "private IPv4 allowed",
			remoteAddr: "192.168.1.1:8080",
			want:       "192.168.1.1",
			wantOK:     true,
		},
		{
			name:       "private 10.x allowed",
			remoteAddr: "10.0.0.1:8080",
			want:       "10.0.0.1",
			wantOK:     true,
		},
		{
			name:       "private 172.16.x allowed",
			remoteAddr: "172.16.0.1:8080",
			want:       "172.16.0.1",
			wantOK:     true,
		},
		{
			name:       "loopback still rejected",
			remoteAddr: "127.0.0.1:8080",
			wantOK:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &http.Request{
				RemoteAddr: tt.remoteAddr,
				Header:     make(http.Header),
			}

			result, err := extractor.Extract(req)

			if (err == nil && result.IP.IsValid()) != tt.wantOK {
				t.Errorf("OK() = %v, want %v (err: %v)", (err == nil && result.IP.IsValid()), tt.wantOK, err)
			}

			if tt.wantOK {
				want := netip.MustParseAddr(tt.want)
				if result.IP != want {
					t.Errorf("IP = %v, want %v", result.IP, want)
				}
			}
		})
	}
}

func TestExtract_WithAllowedReservedClientPrefixes(t *testing.T) {
	t.Run("remote reserved allowed", func(t *testing.T) {
		extractor, err := New(WithAllowedReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24")))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "198.51.100.10:8080", Header: make(http.Header)}
		result, err := extractor.Extract(req)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}

		if got, want := result.IP, netip.MustParseAddr("198.51.100.10"); got != want {
			t.Fatalf("IP = %s, want %s", got, want)
		}
		if got, want := result.Source, SourceRemoteAddr; got != want {
			t.Fatalf("Source = %q, want %q", got, want)
		}
	})

	t.Run("remote reserved not allowlisted", func(t *testing.T) {
		extractor, err := New(WithAllowedReservedClientPrefixes(netip.MustParsePrefix("203.0.113.0/24")))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "198.51.100.10:8080", Header: make(http.Header)}
		_, err = extractor.Extract(req)
		if !errors.Is(err, ErrInvalidIP) {
			t.Fatalf("error = %v, want ErrInvalidIP", err)
		}
	})

	t.Run("xff reserved allowed", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceXForwardedFor),
			WithAllowedReservedClientPrefixes(netip.MustParsePrefix("100.64.0.0/10")),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}
		req.Header.Set("X-Forwarded-For", "100.64.0.1")

		result, err := extractor.Extract(req)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}

		if got, want := result.IP, netip.MustParseAddr("100.64.0.1"); got != want {
			t.Fatalf("IP = %s, want %s", got, want)
		}
		if got, want := result.Source, SourceXForwardedFor; got != want {
			t.Fatalf("Source = %q, want %q", got, want)
		}
	})

	t.Run("private still rejected", func(t *testing.T) {
		extractor, err := New(WithAllowedReservedClientPrefixes(netip.MustParsePrefix("192.168.0.0/16")))
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "192.168.1.10:8080", Header: make(http.Header)}
		_, err = extractor.Extract(req)
		if !errors.Is(err, ErrInvalidIP) {
			t.Fatalf("error = %v, want ErrInvalidIP", err)
		}
	})
}

func TestExtract_WithCallOptions_AllowedReservedClientPrefixes(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{RemoteAddr: "198.51.100.10:8080", Header: make(http.Header)}

	_, err = extractor.Extract(req)
	if !errors.Is(err, ErrInvalidIP) {
		t.Fatalf("error = %v, want ErrInvalidIP", err)
	}

	result, err := extractor.Extract(req, WithCallAllowedReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24")))
	if err != nil {
		t.Fatalf("Extract() with call option error = %v", err)
	}

	if got, want := result.IP, netip.MustParseAddr("198.51.100.10"); got != want {
		t.Fatalf("IP = %s, want %s", got, want)
	}
	if got, want := result.Source, SourceRemoteAddr; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}
}

func TestExtract_WithCallOptions_RuntimeOverrides(t *testing.T) {
	t.Run("trusted proxy prefixes override trust decision", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "10.0.0.1:8080", Header: make(http.Header)}
		req.Header.Set("X-Forwarded-For", "8.8.8.8")

		_, err = extractor.Extract(req)
		if !errors.Is(err, ErrUntrustedProxy) {
			t.Fatalf("error = %v, want ErrUntrustedProxy", err)
		}

		result, err := extractor.Extract(req,
			WithCallTrustedProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
		)
		if err != nil {
			t.Fatalf("Extract() with call option error = %v", err)
		}

		if got, want := result.IP, netip.MustParseAddr("8.8.8.8"); got != want {
			t.Fatalf("IP = %s, want %s", got, want)
		}
		if got, want := result.Source, SourceXForwardedFor; got != want {
			t.Fatalf("Source = %q, want %q", got, want)
		}
	})

	t.Run("proxy count bounds override validation", func(t *testing.T) {
		extractor, err := New(
			WithTrustedProxyPrefixes(netip.MustParsePrefix("10.0.0.0/8")),
			WithSourcePriority(SourceXForwardedFor),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "10.0.0.2:8080", Header: make(http.Header)}
		req.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.1, 10.0.0.2")

		_, err = extractor.Extract(req, WithCallMinTrustedProxies(3))
		if !errors.Is(err, ErrTooFewTrustedProxies) {
			t.Fatalf("min-trusted error = %v, want ErrTooFewTrustedProxies", err)
		}

		_, err = extractor.Extract(req, WithCallMaxTrustedProxies(1))
		if !errors.Is(err, ErrTooManyTrustedProxies) {
			t.Fatalf("max-trusted error = %v, want ErrTooManyTrustedProxies", err)
		}
	})

	t.Run("max chain length override applies at extraction time", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceXForwardedFor),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}
		req.Header.Set("X-Forwarded-For", "8.8.8.8, 9.9.9.9")

		_, err = extractor.Extract(req, WithCallMaxChainLength(1))
		if !errors.Is(err, ErrChainTooLong) {
			t.Fatalf("error = %v, want ErrChainTooLong", err)
		}
	})

	t.Run("chain selection and debug info can both be overridden", func(t *testing.T) {
		extractor, err := New(
			WithTrustedProxyPrefixes(netip.MustParsePrefix("173.245.48.0/20")),
			WithSourcePriority(SourceXForwardedFor),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "173.245.48.5:443", Header: make(http.Header)}
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8, 173.245.48.5")

		result, err := extractor.Extract(req)
		if err != nil {
			t.Fatalf("Extract() error = %v", err)
		}
		if got, want := result.IP.String(), "8.8.8.8"; got != want {
			t.Fatalf("default IP = %q, want %q", got, want)
		}
		if result.DebugInfo != nil {
			t.Fatal("default extraction should not include debug info")
		}

		result, err = extractor.Extract(req,
			WithCallChainSelection(LeftmostUntrustedIP),
			WithCallDebugInfo(true),
		)
		if err != nil {
			t.Fatalf("Extract() with call options error = %v", err)
		}
		if got, want := result.IP.String(), "1.1.1.1"; got != want {
			t.Fatalf("override IP = %q, want %q", got, want)
		}
		if result.DebugInfo == nil {
			t.Fatal("override extraction should include debug info")
		}
	})

	t.Run("allow private IPs can be enabled per call", func(t *testing.T) {
		extractor, err := New()
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{RemoteAddr: "192.168.1.10:8080", Header: make(http.Header)}

		_, err = extractor.Extract(req)
		if !errors.Is(err, ErrInvalidIP) {
			t.Fatalf("error = %v, want ErrInvalidIP", err)
		}

		result, err := extractor.Extract(req, WithCallAllowPrivateIPs(true))
		if err != nil {
			t.Fatalf("Extract() with call option error = %v", err)
		}

		if got, want := result.IP, netip.MustParseAddr("192.168.1.10"); got != want {
			t.Fatalf("IP = %s, want %s", got, want)
		}
		if got, want := result.Source, SourceRemoteAddr; got != want {
			t.Fatalf("Source = %q, want %q", got, want)
		}
	})
}

func TestExtract_WithDebugInfo(t *testing.T) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, err := New(
		WithTrustedProxyPrefixes(cidrs...),
		WithMinTrustedProxies(1),
		WithMaxTrustedProxies(2),
		WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
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

	result, err := extractor.Extract(req)

	if err != nil || !result.IP.IsValid() {
		t.Fatalf("Extract() failed: %v", err)
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

func TestExtract_ErrorTypes(t *testing.T) {
	t.Run("InvalidForwardedHeader", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceForwarded),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("Forwarded", "for=\"1.1.1.1")

		result, err := extractor.Extract(req)

		if err == nil && result.IP.IsValid() {
			t.Error("Expected invalid result for malformed Forwarded header")
		}

		if !errors.Is(err, ErrInvalidForwardedHeader) {
			t.Errorf("Expected error to wrap ErrInvalidForwardedHeader, got %v", err)
		}

		var extractionErr *ExtractionError
		if !errors.As(err, &extractionErr) {
			t.Errorf("Expected ExtractionError, got %T", err)
		}
	})

	t.Run("MultipleXFFHeaders_AreCombined", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceXForwardedFor),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Add("X-Forwarded-For", "8.8.8.8")
		req.Header.Add("X-Forwarded-For", "1.1.1.1")

		result, err := extractor.Extract(req)
		if err != nil {
			t.Fatalf("expected extraction success, got error: %v", err)
		}
		if !result.IP.IsValid() {
			t.Fatal("expected valid result for multiple X-Forwarded-For headers")
		}
		if got, want := result.IP.String(), "1.1.1.1"; got != want {
			t.Errorf("IP = %q, want %q", got, want)
		}
		if got, want := result.Source, SourceXForwardedFor; got != want {
			t.Errorf("Source = %q, want %q", got, want)
		}
	})

	t.Run("MultipleSingleIPHeadersError", func(t *testing.T) {
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceXRealIP),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Add("X-Real-IP", "8.8.8.8")
		req.Header.Add("X-Real-IP", "1.1.1.1")

		result, err := extractor.Extract(req)

		if err == nil && result.IP.IsValid() {
			t.Error("Expected invalid result for multiple single-IP headers")
		}

		var multipleHeadersErr *MultipleHeadersError
		if !errors.As(err, &multipleHeadersErr) {
			t.Errorf("Expected MultipleHeadersError, got %T", err)
		} else {
			if multipleHeadersErr.HeaderCount != 2 {
				t.Errorf("HeaderCount = %d, want 2", multipleHeadersErr.HeaderCount)
			}
			if multipleHeadersErr.HeaderName != "X-Real-IP" {
				t.Errorf("HeaderName = %q, want %q", multipleHeadersErr.HeaderName, "X-Real-IP")
			}
		}

		if !errors.Is(err, ErrMultipleSingleIPHeaders) {
			t.Error("Expected error to wrap ErrMultipleSingleIPHeaders")
		}
	})

	t.Run("ProxyValidationError", func(t *testing.T) {
		cidrs, _ := ParseCIDRs("10.0.0.0/8")
		extractor, err := New(
			WithTrustedProxyPrefixes(cidrs...),
			WithMinTrustedProxies(2),
			WithMaxTrustedProxies(3),
			WithSourcePriority(SourceXForwardedFor),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}

		req := &http.Request{
			RemoteAddr: "10.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

		_, err = extractor.Extract(req)
		if !errors.Is(err, ErrTooFewTrustedProxies) {
			t.Errorf("Expected error to wrap ErrTooFewTrustedProxies, got %v", err)
		}

		var proxyValidationErr *ProxyValidationError
		if !errors.As(err, &proxyValidationErr) {
			t.Errorf("Expected ProxyValidationError, got %T", err)
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
		extractor, err := New(
			WithTrustedLoopbackProxy(),
			WithSourcePriority(SourceXForwardedFor),
		)
		if err != nil {
			t.Fatalf("New() error = %v", err)
		}
		req := &http.Request{
			RemoteAddr: "127.0.0.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Set("X-Forwarded-For", "192.168.1.1")

		_, err = extractor.Extract(req)

		var invalidIPErr *InvalidIPError
		if !errors.As(err, &invalidIPErr) {
			t.Errorf("Expected InvalidIPError, got %T", err)
		}
	})
}

func TestExtract_IPv4MappedIPv6(t *testing.T) {
	extractor := mustNewExtractor(t)

	req := &http.Request{
		RemoteAddr: "[::ffff:1.1.1.1]:8080",
		Header:     make(http.Header),
	}

	result, err := extractor.Extract(req)

	if err != nil || !result.IP.IsValid() {
		t.Fatalf("Extract() failed: %v", err)
	}

	if !result.IP.Is4() {
		t.Errorf("Expected IPv4 address, got %v", result.IP)
	}

	want := netip.MustParseAddr("1.1.1.1")
	if result.IP != want {
		t.Errorf("IP = %v, want %v", result.IP, want)
	}
}

func TestExtract_Concurrent(t *testing.T) {
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
			result, err := extractor.Extract(req)
			if err != nil || !result.IP.IsValid() {
				errors <- err
			} else {
				want := netip.MustParseAddr("1.1.1.1")
				if result.IP != want {
					errors <- &ExtractionError{Err: ErrInvalidIP, Source: HeaderSource("test")}
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

func TestExtract_ContextPropagation(t *testing.T) {
	extractor := mustNewExtractor(t)

	ctx := context.WithValue(context.Background(), contextKey("test-key"), "test-value")
	req := &http.Request{
		RemoteAddr: "1.1.1.1:8080",
		Header:     make(http.Header),
	}
	req = req.WithContext(ctx)

	result, err := extractor.Extract(req)

	if err != nil || !result.IP.IsValid() {
		t.Errorf("Extract() failed: %v", err)
	}
}

func TestExtract_NewAPI_Methods(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{RemoteAddr: "1.1.1.1:8080", Header: make(http.Header)}

	type extractionView struct {
		IP                string
		Source            Source
		TrustedProxyCount int
		HasDebugInfo      bool
	}

	toView := func(e Extraction) extractionView {
		return extractionView{
			IP:                e.IP.String(),
			Source:            e.Source,
			TrustedProxyCount: e.TrustedProxyCount,
			HasDebugInfo:      e.DebugInfo != nil,
		}
	}

	tests := []struct {
		name           string
		callExtraction bool
		wantExtraction extractionView
		wantAddr       string
	}{
		{
			name:           "Extract",
			callExtraction: true,
			wantExtraction: extractionView{IP: "1.1.1.1", Source: SourceRemoteAddr, TrustedProxyCount: 0, HasDebugInfo: false},
		},
		{
			name:     "ExtractAddr",
			wantAddr: "1.1.1.1",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.callExtraction {
				got, err := extractor.Extract(req)
				if err != nil {
					t.Fatalf("Extract() error = %v", err)
				}

				if diff := cmp.Diff(tt.wantExtraction, toView(got)); diff != "" {
					t.Fatalf("extraction mismatch (-want +got):\n%s", diff)
				}
				return
			}

			gotAddr, err := extractor.ExtractAddr(req)
			if err != nil {
				t.Fatalf("ExtractAddr() error = %v", err)
			}
			if diff := cmp.Diff(tt.wantAddr, gotAddr.String()); diff != "" {
				t.Fatalf("addr mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestExtract_WithCallOptions_LastWins(t *testing.T) {
	extractor, err := New(
		WithTrustedProxyAddrs(netip.MustParseAddr("127.0.0.1")),
		WithSourcePriority(HeaderSource("X-Frontend-IP"), SourceXForwardedFor, SourceRemoteAddr),
		WithSecurityMode(SecurityModeStrict),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}
	req.Header.Set("X-Frontend-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	tests := []struct {
		name     string
		callOpts []CallOption
		wantErr  bool
		want     struct {
			IP     string
			Source Source
		}
	}{
		{
			name:     "strict default fails",
			callOpts: nil,
			wantErr:  true,
		},
		{
			name: "lax call options succeed",
			callOpts: []CallOption{
				WithCallSecurityMode(SecurityModeStrict),
				WithCallSecurityMode(SecurityModeLax),
			},
			want: struct {
				IP     string
				Source Source
			}{IP: "8.8.8.8", Source: SourceXForwardedFor},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := extractor.Extract(req, tt.callOpts...)
			if tt.wantErr {
				if err == nil {
					t.Fatal("Extract() error = nil, want non-nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			gotView := struct {
				IP     string
				Source Source
			}{IP: got.IP.String(), Source: got.Source}

			if diff := cmp.Diff(tt.want, gotView); diff != "" {
				t.Fatalf("extraction mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestPrepareCall_NoEffectiveChanges_ReusesExtractorAndSource(t *testing.T) {
	extractor, err := New(
		WithTrustedLoopbackProxy(),
		WithSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
		WithSecurityMode(SecurityModeStrict),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	activeExtractor, activeSource, err := extractor.prepareCall(
		WithCallSecurityMode(SecurityModeStrict),
		WithCallSourcePriority(SourceXForwardedFor, SourceRemoteAddr),
	)
	if err != nil {
		t.Fatalf("prepareCall() error = %v", err)
	}

	if activeExtractor != extractor {
		t.Fatal("prepareCall() should reuse extractor when call options do not change policy")
	}

	if activeSource != extractor.source {
		t.Fatal("prepareCall() should reuse source chain when call options do not change policy")
	}
}

func TestExtract_NilRequest(t *testing.T) {
	extractor, err := New()
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, extractErr := extractor.Extract(nil)
	if !errors.Is(extractErr, ErrNilRequest) {
		t.Fatalf("error = %v, want ErrNilRequest", extractErr)
	}

	gotAddr, extractErr := extractor.ExtractAddr(nil)
	if !errors.Is(extractErr, ErrNilRequest) {
		t.Fatalf("error = %v, want ErrNilRequest", extractErr)
	}

	if diff := cmp.Diff(false, gotAddr.IsValid()); diff != "" {
		t.Fatalf("address validity mismatch (-want +got):\n%s", diff)
	}
}

func TestExtract_ErrorSourceReporting(t *testing.T) {
	t.Run("source-aware error keeps source", func(t *testing.T) {
		extractor := mustNewExtractor(
			t,
			WithTrustedProxyAddrs(netip.MustParseAddr("1.1.1.1")),
			WithSourcePriority(SourceXRealIP),
		)

		req := &http.Request{
			RemoteAddr: "1.1.1.1:8080",
			Header:     make(http.Header),
		}
		req.Header.Add("X-Real-IP", "8.8.8.8")
		req.Header.Add("X-Real-IP", "9.9.9.9")

		result, err := extractor.Extract(req)
		if !errors.Is(err, ErrMultipleSingleIPHeaders) {
			t.Fatalf("error = %v, want ErrMultipleSingleIPHeaders", err)
		}

		got := extractionStateOf(result)
		want := extractionState{Source: SourceXRealIP, HasIP: false}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("error result mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("non source-aware error leaves source empty", func(t *testing.T) {
		extractor := mustNewExtractor(t)

		ctx, cancel := context.WithCancel(context.Background())
		cancel()

		req := (&http.Request{
			RemoteAddr: "1.1.1.1:8080",
			Header:     make(http.Header),
		}).WithContext(ctx)

		result, err := extractor.Extract(req)
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("error = %v, want context.Canceled", err)
		}

		got := extractionStateOf(result)
		want := extractionState{Source: Source{}, HasIP: false}

		if diff := cmp.Diff(want, got); diff != "" {
			t.Fatalf("error result mismatch (-want +got):\n%s", diff)
		}
	})
}

func TestNew_OptionsImmutability(t *testing.T) {
	trusted := []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}
	priority := []Source{SourceXForwardedFor, SourceRemoteAddr}

	extractor, err := New(
		WithTrustedProxyPrefixes(trusted...),
		WithMinTrustedProxies(0),
		WithMaxTrustedProxies(0),
		WithSourcePriority(priority...),
	)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	trusted[0] = netip.MustParsePrefix("10.0.0.0/8")
	priority[0] = SourceRemoteAddr

	req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	got, err := extractor.Extract(req)
	if err != nil {
		t.Fatalf("Extract() error = %v", err)
	}

	want := struct {
		IP     string
		Source Source
	}{IP: "8.8.8.8", Source: SourceXForwardedFor}
	gotView := struct {
		IP     string
		Source Source
	}{IP: got.IP.String(), Source: got.Source}

	if diff := cmp.Diff(want, gotView); diff != "" {
		t.Fatalf("immutability extraction mismatch (-want +got):\n%s", diff)
	}
}

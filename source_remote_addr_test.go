package clientip

import (
	"context"
	"net/http"
	"net/netip"
	"testing"
)

func TestRemoteAddrSource_Extract(t *testing.T) {
	extractor := mustNewExtractor(t)
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
	extractor := mustNewExtractor(t)
	source := &remoteAddrSource{extractor: extractor}

	if source.Name() != SourceRemoteAddr {
		t.Errorf("Name() = %q, want %q", source.Name(), SourceRemoteAddr)
	}
}

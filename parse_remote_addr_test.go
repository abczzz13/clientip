package clientip

import (
	"errors"
	"testing"
)

func TestParseRemoteAddr(t *testing.T) {
	tests := []struct {
		name        string
		remoteAddr  string
		wantIP      string
		wantErr     error
		wantErrType any
	}{
		{name: "host port", remoteAddr: "8.8.8.8:443", wantIP: "8.8.8.8"},
		{name: "bracketed ipv6 host port", remoteAddr: "[2001:db8::1]:443", wantIP: "2001:db8::1"},
		{name: "bare ip", remoteAddr: "2001:db8::1", wantIP: "2001:db8::1"},
		{name: "mapped ipv4 normalized", remoteAddr: "[::ffff:192.0.2.10]:443", wantIP: "192.0.2.10"},
		{name: "empty", wantErr: ErrSourceUnavailable, wantErrType: &ExtractionError{}},
		{name: "invalid", remoteAddr: "bad-remote-addr", wantErr: ErrInvalidIP, wantErrType: &RemoteAddrError{}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseRemoteAddr(tt.remoteAddr)
			if tt.wantErr != nil {
				if !errors.Is(err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", err, tt.wantErr)
				}
				if !errorIsType(err, tt.wantErrType) {
					t.Fatalf("error type = %T, want %T", err, tt.wantErrType)
				}
				return
			}

			if err != nil {
				t.Fatalf("ParseRemoteAddr() error = %v", err)
			}
			if got.String() != tt.wantIP {
				t.Fatalf("IP = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

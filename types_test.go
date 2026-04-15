package clientip

import (
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name:  "valid single CIDR",
			cidrs: []string{"10.0.0.0/8"},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
			},
			wantErr: false,
		},
		{
			name:  "valid multiple CIDRs",
			cidrs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			wantErr: false,
		},
		{
			name:  "valid IPv6 CIDR",
			cidrs: []string{"2001:db8::/32"},
			want: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
			},
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			cidrs:   []string{"10.0.0.0"},
			wantErr: true,
		},
		{
			name:    "invalid CIDR in list",
			cidrs:   []string{"10.0.0.0/8", "invalid", "192.168.0.0/16"},
			wantErr: true,
		},
		{
			name:    "empty string",
			cidrs:   []string{""},
			wantErr: true,
		},
		{
			name:    "empty list",
			cidrs:   []string{},
			want:    []netip.Prefix{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCIDRs(tt.cidrs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDRs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ParseCIDRs() got %d prefixes, want %d", len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("ParseCIDRs()[%d] = %v, want %v", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestSetValue_Behavior(t *testing.T) {
	type setValueObservation struct {
		Set   bool
		Value any
	}

	tests := []struct {
		name string
		run  func() setValueObservation
		want setValueObservation
	}{
		{
			name: "zero int value is not set",
			run: func() setValueObservation {
				var v SetValue[int]
				return setValueObservation{Set: v.isSet(), Value: v.value()}
			},
			want: setValueObservation{Set: false, Value: 0},
		},
		{
			name: "Set marks int as set",
			run: func() setValueObservation {
				v := Set(42)
				return setValueObservation{Set: v.isSet(), Value: v.value()}
			},
			want: setValueObservation{Set: true, Value: 42},
		},
		{
			name: "zero bool value is not set",
			run: func() setValueObservation {
				var v SetValue[bool]
				return setValueObservation{Set: v.isSet(), Value: v.value()}
			},
			want: setValueObservation{Set: false, Value: false},
		},
		{
			name: "Set marks false bool as set",
			run: func() setValueObservation {
				v := Set(false)
				return setValueObservation{Set: v.isSet(), Value: v.value()}
			},
			want: setValueObservation{Set: true, Value: false},
		},
		{
			name: "Set preserves nil slice value",
			run: func() setValueObservation {
				var nilSlice []string
				v := Set(nilSlice)
				return setValueObservation{Set: v.isSet(), Value: v.value()}
			},
			want: setValueObservation{Set: true, Value: []string(nil)},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.run()); diff != "" {
				t.Fatalf("SetValue mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestTypedErrors_ErrorFormatting(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ExtractionError",
			err:  &ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
			want: "remote_addr: invalid or implausible IP address",
		},
		{
			name: "MultipleHeadersError with header name",
			err: &MultipleHeadersError{
				ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: SourceXRealIP},
				HeaderCount:     2,
				HeaderName:      "X-Real-IP",
				RemoteAddr:      "1.1.1.1:12345",
			},
			want: `x_real_ip: multiple single-IP headers received (header="X-Real-IP", header_count=2, remote_addr=1.1.1.1:12345)`,
		},
		{
			name: "MultipleHeadersError without header name",
			err: &MultipleHeadersError{
				ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: SourceXRealIP},
				HeaderCount:     3,
				RemoteAddr:      "2.2.2.2:4321",
			},
			want: `x_real_ip: multiple single-IP headers received (header_count=3, remote_addr=2.2.2.2:4321)`,
		},
		{
			name: "ProxyValidationError",
			err: &ProxyValidationError{
				ExtractionError:   ExtractionError{Err: ErrTooFewTrustedProxies, Source: SourceXForwardedFor},
				Chain:             "1.1.1.1, 10.0.0.1",
				TrustedProxyCount: 1,
				MinTrustedProxies: 2,
				MaxTrustedProxies: 3,
			},
			want: `x_forwarded_for: too few trusted proxies in proxy chain (chain="1.1.1.1, 10.0.0.1", trusted_count=1, min=2, max=3)`,
		},
		{
			name: "InvalidIPError with chain",
			err: &InvalidIPError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceXForwardedFor},
				Chain:           "not-an-ip, 10.0.0.1",
				ExtractedIP:     "not-an-ip",
				Index:           0,
				TrustedProxies:  1,
			},
			want: `x_forwarded_for: invalid or implausible IP address (chain="not-an-ip, 10.0.0.1", extracted_ip="not-an-ip", index=0, trusted_proxies=1)`,
		},
		{
			name: "InvalidIPError with extracted IP only",
			err: &InvalidIPError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceXRealIP},
				ExtractedIP:     "not-an-ip",
			},
			want: `x_real_ip: invalid or implausible IP address (ip="not-an-ip")`,
		},
		{
			name: "InvalidIPError falls back to ExtractionError formatting",
			err: &InvalidIPError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
			},
			want: "remote_addr: invalid or implausible IP address",
		},
		{
			name: "RemoteAddrError",
			err: &RemoteAddrError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
				RemoteAddr:      "bad-remote-addr",
			},
			want: `remote_addr: invalid or implausible IP address (remote_addr="bad-remote-addr")`,
		},
		{
			name: "ChainTooLongError",
			err: &ChainTooLongError{
				ExtractionError: ExtractionError{Err: ErrChainTooLong, Source: SourceForwarded},
				ChainLength:     6,
				MaxLength:       5,
			},
			want: "forwarded: proxy chain too long (chain_length=6, max_length=5)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.err.Error()); diff != "" {
				t.Fatalf("error string mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

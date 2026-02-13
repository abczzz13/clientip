package clientip

import (
	"net/netip"
	"testing"
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

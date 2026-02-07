package clientip

import (
	"net/netip"
	"testing"
)

func TestParseXFFValues(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []string
	}{
		{
			name:   "single value",
			values: []string{"1.1.1.1"},
			want:   []string{"1.1.1.1"},
		},
		{
			name:   "single value with multiple IPs",
			values: []string{"1.1.1.1, 8.8.8.8"},
			want:   []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:   "multiple values combined",
			values: []string{"1.1.1.1", "8.8.8.8"},
			want:   []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:   "whitespace trimmed",
			values: []string{"  1.1.1.1  ,  8.8.8.8  "},
			want:   []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:   "empty strings ignored",
			values: []string{"1.1.1.1, , 8.8.8.8"},
			want:   []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:   "empty list",
			values: []string{},
			want:   nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, _ := New()
			got, err := extractor.parseXFFValues(tt.values)
			if err != nil {
				t.Fatalf("parseXFFValues() error = %v, want nil", err)
			}

			if len(got) != len(tt.want) {
				t.Errorf("parseXFFValues() length = %d, want %d", len(got), len(tt.want))
				return
			}

			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("parseXFFValues()[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestParseXFFValues_MaxChainLength(t *testing.T) {
	extractor, err := New(MaxChainLength(5))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	values := []string{"1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6, 7.7.7.7"}
	_, err = extractor.parseXFFValues(values)

	if !errorContains(err, ErrChainTooLong) {
		t.Errorf("parseXFFValues() error = %v, want ErrChainTooLong", err)
	}
}

func TestIsTrustedProxy(t *testing.T) {
	cidrs, err := ParseCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	if err != nil {
		t.Fatalf("ParseCIDRs() error = %v", err)
	}

	extractor := &Extractor{
		config: &Config{
			trustedProxyCIDRs: cidrs,
		},
	}

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{
			name: "10.x.x.x trusted",
			ip:   "10.0.0.1",
			want: true,
		},
		{
			name: "172.16.x.x trusted",
			ip:   "172.16.0.1",
			want: true,
		},
		{
			name: "192.168.x.x trusted",
			ip:   "192.168.1.1",
			want: true,
		},
		{
			name: "public IP not trusted",
			ip:   "1.1.1.1",
			want: false,
		},
		{
			name: "invalid IP not trusted",
			ip:   "invalid",
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := parseIP(tt.ip)
			got := extractor.isTrustedProxy(ip)
			if got != tt.want {
				t.Errorf("isTrustedProxy(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestValidateProxyCount(t *testing.T) {
	tests := []struct {
		name         string
		minProxies   int
		maxProxies   int
		trustedCIDRs []netip.Prefix
		trustedCount int
		wantErr      error
	}{
		{
			name:         "within range",
			minProxies:   1,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 2,
			wantErr:      nil,
		},
		{
			name:         "at minimum",
			minProxies:   1,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 1,
			wantErr:      nil,
		},
		{
			name:         "at maximum",
			minProxies:   1,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 3,
			wantErr:      nil,
		},
		{
			name:         "no trusted proxies allowed when minimum is zero",
			minProxies:   0,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 0,
			wantErr:      nil,
		},
		{
			name:         "no trusted proxies with minimum requirement",
			minProxies:   1,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 0,
			wantErr:      ErrNoTrustedProxies,
		},
		{
			name:         "below minimum",
			minProxies:   2,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 1,
			wantErr:      ErrTooFewTrustedProxies,
		},
		{
			name:         "above maximum",
			minProxies:   1,
			maxProxies:   2,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 3,
			wantErr:      ErrTooManyTrustedProxies,
		},
		{
			name:         "no minimum requirement",
			minProxies:   0,
			maxProxies:   3,
			trustedCIDRs: []netip.Prefix{},
			trustedCount: 0,
			wantErr:      nil,
		},
		{
			name:         "no maximum limit",
			minProxies:   1,
			maxProxies:   0,
			trustedCIDRs: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")},
			trustedCount: 100,
			wantErr:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &Extractor{
				config: &Config{
					minTrustedProxies: tt.minProxies,
					maxTrustedProxies: tt.maxProxies,
					trustedProxyCIDRs: tt.trustedCIDRs,
					metrics:           noopMetrics{},
				},
			}

			err := extractor.validateProxyCount(tt.trustedCount)
			if tt.wantErr == nil {
				if err != nil {
					t.Errorf("validateProxyCount() error = %v, want nil", err)
				}
				return
			}

			if !errorContains(err, tt.wantErr) {
				t.Errorf("validateProxyCount() error = %v, want %v", err, tt.wantErr)
			}
		})
	}
}

func TestAnalyzeChainRightmost_NoCIDRs(t *testing.T) {
	tests := []struct {
		name              string
		parts             []string
		maxTrustedProxies int
		wantClientIndex   int
		wantTrustedCount  int
	}{
		{
			name:              "no max proxies",
			parts:             []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"},
			maxTrustedProxies: 0,
			wantClientIndex:   0,
			wantTrustedCount:  3,
		},
		{
			name:              "max 1 proxy",
			parts:             []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"},
			maxTrustedProxies: 1,
			wantClientIndex:   1,
			wantTrustedCount:  1,
		},
		{
			name:              "max 2 proxies",
			parts:             []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"},
			maxTrustedProxies: 2,
			wantClientIndex:   0,
			wantTrustedCount:  2,
		},
		{
			name:              "single IP",
			parts:             []string{"1.1.1.1"},
			maxTrustedProxies: 1,
			wantClientIndex:   0,
			wantTrustedCount:  1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &Extractor{
				config: &Config{
					trustedProxyCIDRs: []netip.Prefix{},
					maxTrustedProxies: tt.maxTrustedProxies,
					metrics:           noopMetrics{},
				},
			}

			analysis, err := extractor.analyzeChainRightmost(tt.parts)
			if err != nil {
				t.Fatalf("analyzeChainRightmost() error = %v", err)
			}

			if analysis.clientIndex != tt.wantClientIndex {
				t.Errorf("clientIndex = %d, want %d", analysis.clientIndex, tt.wantClientIndex)
			}

			if analysis.trustedCount != tt.wantTrustedCount {
				t.Errorf("trustedCount = %d, want %d", analysis.trustedCount, tt.wantTrustedCount)
			}
		})
	}
}

func TestAnalyzeChainRightmost_WithCIDRs(t *testing.T) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")

	tests := []struct {
		name               string
		parts              []string
		minProxies         int
		maxProxies         int
		wantClientIndex    int
		wantTrustedCount   int
		wantErr            error
		wantTrustedIndices []int
	}{
		{
			name:               "one trusted proxy at end",
			parts:              []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"},
			minProxies:         0,
			maxProxies:         2,
			wantClientIndex:    1,
			wantTrustedCount:   1,
			wantTrustedIndices: []int{2},
		},
		{
			name:               "two trusted proxies at end",
			parts:              []string{"1.1.1.1", "10.0.0.1", "10.0.0.2"},
			minProxies:         0,
			maxProxies:         2,
			wantClientIndex:    0,
			wantTrustedCount:   2,
			wantTrustedIndices: []int{2, 1},
		},
		{
			name:               "no trusted proxies allowed when minimum is zero",
			parts:              []string{"1.1.1.1", "8.8.8.8"},
			minProxies:         0,
			maxProxies:         2,
			wantClientIndex:    1,
			wantTrustedCount:   0,
			wantTrustedIndices: []int{},
		},
		{
			name:               "no trusted proxies with minimum requirement",
			parts:              []string{"1.1.1.1", "8.8.8.8"},
			minProxies:         1,
			maxProxies:         2,
			wantClientIndex:    1,
			wantTrustedCount:   0,
			wantErr:            ErrNoTrustedProxies,
			wantTrustedIndices: []int{},
		},
		{
			name:               "too many trusted proxies",
			parts:              []string{"1.1.1.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
			minProxies:         0,
			maxProxies:         2,
			wantClientIndex:    0,
			wantTrustedCount:   3,
			wantErr:            ErrTooManyTrustedProxies,
			wantTrustedIndices: []int{3, 2, 1},
		},
		{
			name:             "below min proxies",
			parts:            []string{"1.1.1.1", "10.0.0.1"},
			minProxies:       2,
			maxProxies:       3,
			wantErr:          ErrTooFewTrustedProxies,
			wantClientIndex:  0,
			wantTrustedCount: 1,
		},
		{
			name:               "mixed trusted and untrusted",
			parts:              []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "198.51.100.2", "10.0.0.2"},
			minProxies:         0,
			maxProxies:         3,
			wantClientIndex:    3,
			wantTrustedCount:   1,
			wantTrustedIndices: []int{4},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &Extractor{
				config: &Config{
					trustedProxyCIDRs: cidrs,
					minTrustedProxies: tt.minProxies,
					maxTrustedProxies: tt.maxProxies,
					metrics:           noopMetrics{},
				},
			}

			analysis, err := extractor.analyzeChainRightmost(tt.parts)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("analyzeChainRightmost() error = %v, want nil", err)
				}
			} else if !errorContains(err, tt.wantErr) {
				t.Fatalf("analyzeChainRightmost() error = %v, want %v", err, tt.wantErr)
			}

			if analysis.clientIndex != tt.wantClientIndex {
				t.Errorf("clientIndex = %d, want %d", analysis.clientIndex, tt.wantClientIndex)
			}

			if analysis.trustedCount != tt.wantTrustedCount {
				t.Errorf("trustedCount = %d, want %d", analysis.trustedCount, tt.wantTrustedCount)
			}

			if tt.wantErr == nil && tt.wantTrustedIndices != nil {
				if len(analysis.trustedIndices) != len(tt.wantTrustedIndices) {
					t.Errorf("trustedIndices length = %d, want %d", len(analysis.trustedIndices), len(tt.wantTrustedIndices))
				} else {
					for i, idx := range tt.wantTrustedIndices {
						if analysis.trustedIndices[i] != idx {
							t.Errorf("trustedIndices[%d] = %d, want %d", i, analysis.trustedIndices[i], idx)
						}
					}
				}
			}
		})
	}
}

func TestAnalyzeChainLeftmost_WithCIDRs(t *testing.T) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")

	tests := []struct {
		name             string
		parts            []string
		minProxies       int
		maxProxies       int
		wantClientIndex  int
		wantTrustedCount int
		wantErr          error
	}{
		{
			name:             "one trusted proxy at end",
			parts:            []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"},
			minProxies:       0,
			maxProxies:       2,
			wantClientIndex:  0,
			wantTrustedCount: 1,
		},
		{
			name:             "two trusted proxies at end",
			parts:            []string{"1.1.1.1", "10.0.0.1", "10.0.0.2"},
			minProxies:       0,
			maxProxies:       2,
			wantClientIndex:  0,
			wantTrustedCount: 2,
		},
		{
			name:             "all trusted proxies",
			parts:            []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			minProxies:       0,
			maxProxies:       3,
			wantClientIndex:  0,
			wantTrustedCount: 3,
		},
		{
			name:             "no trusted proxies allowed when minimum is zero",
			parts:            []string{"1.1.1.1", "8.8.8.8"},
			minProxies:       0,
			maxProxies:       2,
			wantClientIndex:  0,
			wantTrustedCount: 0,
		},
		{
			name:             "no trusted proxies with minimum requirement",
			parts:            []string{"1.1.1.1", "8.8.8.8"},
			minProxies:       1,
			maxProxies:       2,
			wantClientIndex:  0,
			wantTrustedCount: 0,
			wantErr:          ErrNoTrustedProxies,
		},
		{
			name:             "too many trusted proxies",
			parts:            []string{"1.1.1.1", "10.0.0.1", "10.0.0.2", "10.0.0.3"},
			minProxies:       0,
			maxProxies:       2,
			wantClientIndex:  0,
			wantTrustedCount: 3,
			wantErr:          ErrTooManyTrustedProxies,
		},
		{
			name:             "below min proxies",
			parts:            []string{"1.1.1.1", "10.0.0.1"},
			minProxies:       2,
			maxProxies:       3,
			wantClientIndex:  0,
			wantTrustedCount: 1,
			wantErr:          ErrTooFewTrustedProxies,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &Extractor{
				config: &Config{
					trustedProxyCIDRs: cidrs,
					minTrustedProxies: tt.minProxies,
					maxTrustedProxies: tt.maxProxies,
					metrics:           noopMetrics{},
				},
			}

			analysis, err := extractor.analyzeChainLeftmost(tt.parts)

			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("analyzeChainLeftmost() error = %v, want nil", err)
				}
			} else if !errorContains(err, tt.wantErr) {
				t.Fatalf("analyzeChainLeftmost() error = %v, want %v", err, tt.wantErr)
			}

			if analysis.clientIndex != tt.wantClientIndex {
				t.Errorf("clientIndex = %d, want %d", analysis.clientIndex, tt.wantClientIndex)
			}

			if analysis.trustedCount != tt.wantTrustedCount {
				t.Errorf("trustedCount = %d, want %d", analysis.trustedCount, tt.wantTrustedCount)
			}
		})
	}
}

func TestSelectLeftmostUntrustedIP(t *testing.T) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")

	tests := []struct {
		name                    string
		parts                   []string
		trustedProxiesFromRight int
		wantIndex               int
	}{
		{
			name:                    "first IP untrusted",
			parts:                   []string{"1.1.1.1", "8.8.8.8", "10.0.0.1"},
			trustedProxiesFromRight: 1,
			wantIndex:               0,
		},
		{
			name:                    "second IP untrusted",
			parts:                   []string{"10.0.0.1", "1.1.1.1", "10.0.0.2"},
			trustedProxiesFromRight: 1,
			wantIndex:               1,
		},
		{
			name:                    "all IPs trusted",
			parts:                   []string{"10.0.0.1", "10.0.0.2", "10.0.0.3"},
			trustedProxiesFromRight: 3,
			wantIndex:               0,
		},
		{
			name:                    "no trusted proxies",
			parts:                   []string{"1.1.1.1", "8.8.8.8"},
			trustedProxiesFromRight: 0,
			wantIndex:               0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &Extractor{
				config: &Config{
					trustedProxyCIDRs: cidrs,
				},
			}

			got := extractor.selectLeftmostUntrustedIP(tt.parts, tt.trustedProxiesFromRight)
			if got != tt.wantIndex {
				t.Errorf("selectLeftmostUntrustedIP() = %d, want %d", got, tt.wantIndex)
			}
		})
	}
}

func TestIsPlausibleClientIP(t *testing.T) {
	tests := []struct {
		name          string
		ip            string
		allowPrivate  bool
		wantPlausible bool
	}{
		{
			name:          "public IPv4",
			ip:            "1.1.1.1",
			allowPrivate:  false,
			wantPlausible: true,
		},
		{
			name:          "public IPv6",
			ip:            "2606:4700:4700::1",
			allowPrivate:  false,
			wantPlausible: true,
		},
		{
			name:          "loopback IPv4",
			ip:            "127.0.0.1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "loopback IPv6",
			ip:            "::1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "link-local IPv4",
			ip:            "169.254.1.1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "link-local IPv6",
			ip:            "fe80::1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "multicast IPv4",
			ip:            "224.0.0.1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "multicast IPv6",
			ip:            "ff02::1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "unspecified IPv4",
			ip:            "0.0.0.0",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "unspecified IPv6",
			ip:            "::",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "private IPv4 rejected",
			ip:            "192.168.1.1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "private IPv4 allowed",
			ip:            "192.168.1.1",
			allowPrivate:  true,
			wantPlausible: true,
		},
		{
			name:          "10.x private rejected",
			ip:            "10.0.0.1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "10.x private allowed",
			ip:            "10.0.0.1",
			allowPrivate:  true,
			wantPlausible: true,
		},
		{
			name:          "172.16.x private rejected",
			ip:            "172.16.0.1",
			allowPrivate:  false,
			wantPlausible: false,
		},
		{
			name:          "invalid IP",
			ip:            "invalid",
			allowPrivate:  false,
			wantPlausible: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := &Extractor{
				config: &Config{
					allowPrivateIPs: tt.allowPrivate,
					metrics:         noopMetrics{},
				},
			}

			ip := parseIP(tt.ip)
			got := extractor.isPlausibleClientIP(ip)

			if got != tt.wantPlausible {
				t.Errorf("isPlausibleClientIP(%s) = %v, want %v", tt.ip, got, tt.wantPlausible)
			}
		})
	}
}

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		reserved bool
	}{
		// Carrier-Grade NAT (RFC 6598): 100.64.0.0/10
		{
			name:     "CGN start",
			ip:       "100.64.0.0",
			reserved: true,
		},
		{
			name:     "CGN middle",
			ip:       "100.100.100.100",
			reserved: true,
		},
		{
			name:     "CGN end",
			ip:       "100.127.255.255",
			reserved: true,
		},
		{
			name:     "Not CGN - before",
			ip:       "100.63.255.255",
			reserved: false,
		},
		{
			name:     "Not CGN - after",
			ip:       "100.128.0.0",
			reserved: false,
		},
		// Documentation IPv4 (RFC 5737) - REJECTED
		{
			name:     "TEST-NET-1",
			ip:       "192.0.2.1",
			reserved: true,
		},
		{
			name:     "TEST-NET-2",
			ip:       "198.51.100.1",
			reserved: true,
		},
		{
			name:     "TEST-NET-3",
			ip:       "203.0.113.1",
			reserved: true,
		},
		// Documentation IPv6 (RFC 3849) - REJECTED
		{
			name:     "IPv6 doc prefix",
			ip:       "2001:db8::1",
			reserved: true,
		},
		{
			name:     "IPv6 doc prefix end",
			ip:       "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff",
			reserved: true,
		},
		{
			name:     "Not IPv6 doc - different prefix",
			ip:       "2001:db9::1",
			reserved: false,
		},
		// Regular addresses should not be reserved
		{
			name:     "Public IPv4",
			ip:       "8.8.8.8",
			reserved: false,
		},
		{
			name:     "Private IPv4",
			ip:       "192.168.1.1",
			reserved: false,
		},
		{
			name:     "Public IPv6",
			ip:       "2001:4860:4860::8888",
			reserved: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			got := isReservedIP(ip)
			if got != tt.reserved {
				t.Errorf("isReservedIP(%s) = %v, want %v", tt.ip, got, tt.reserved)
			}
		})
	}
}

func TestIsPlausibleClientIP_ReservedRanges(t *testing.T) {
	extractor := &Extractor{
		config: &Config{
			allowPrivateIPs: true, // Allow private but still reject reserved
			metrics:         noopMetrics{},
		},
	}

	tests := []struct {
		name   string
		ip     string
		wantOk bool
	}{
		{
			name:   "CGN rejected",
			ip:     "100.64.0.1",
			wantOk: false,
		},
		{
			name:   "TEST-NET-1 rejected",
			ip:     "192.0.2.1",
			wantOk: false,
		},
		{
			name:   "TEST-NET-2 rejected",
			ip:     "198.51.100.1",
			wantOk: false,
		},
		{
			name:   "TEST-NET-3 rejected",
			ip:     "203.0.113.1",
			wantOk: false,
		},
		{
			name:   "IPv6 doc rejected",
			ip:     "2001:db8::1",
			wantOk: false,
		},
		{
			name:   "Private allowed when configured",
			ip:     "192.168.1.1",
			wantOk: true,
		},
		{
			name:   "Public allowed",
			ip:     "8.8.8.8",
			wantOk: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ip := netip.MustParseAddr(tt.ip)
			got := extractor.isPlausibleClientIP(ip)
			if got != tt.wantOk {
				t.Errorf("isPlausibleClientIP(%s) = %v, want %v", tt.ip, got, tt.wantOk)
			}
		})
	}
}

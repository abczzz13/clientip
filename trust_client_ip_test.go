package clientip

import (
	"net/netip"
	"testing"
)

func TestEvaluateClientIP(t *testing.T) {
	tests := []struct {
		name         string
		ip           string
		allowPrivate bool
		want         clientIPDisposition
	}{
		{name: "public IPv4", ip: "1.1.1.1", want: clientIPValid},
		{name: "public IPv6", ip: "2606:4700:4700::1", want: clientIPValid},
		{name: "loopback IPv4", ip: "127.0.0.1", want: clientIPInvalid},
		{name: "loopback IPv6", ip: "::1", want: clientIPInvalid},
		{name: "link-local IPv4", ip: "169.254.1.1", want: clientIPInvalid},
		{name: "link-local IPv6", ip: "fe80::1", want: clientIPInvalid},
		{name: "multicast IPv4", ip: "224.0.0.1", want: clientIPInvalid},
		{name: "multicast IPv6", ip: "ff02::1", want: clientIPInvalid},
		{name: "unspecified IPv4", ip: "0.0.0.0", want: clientIPInvalid},
		{name: "unspecified IPv6", ip: "::", want: clientIPInvalid},
		{name: "private IPv4 rejected", ip: "192.168.1.1", want: clientIPPrivate},
		{name: "private IPv4 allowed", ip: "192.168.1.1", allowPrivate: true, want: clientIPValid},
		{name: "10.x private rejected", ip: "10.0.0.1", want: clientIPPrivate},
		{name: "10.x private allowed", ip: "10.0.0.1", allowPrivate: true, want: clientIPValid},
		{name: "172.16.x private rejected", ip: "172.16.0.1", want: clientIPPrivate},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateClientIP(netip.MustParseAddr(tt.ip), clientIPPolicy{AllowPrivateIPs: tt.allowPrivate})
			if got != tt.want {
				t.Errorf("evaluateClientIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}

	if got := evaluateClientIP(netip.Addr{}, clientIPPolicy{}); got != clientIPInvalid {
		t.Fatalf("evaluateClientIP(invalid) = %v, want %v", got, clientIPInvalid)
	}
}

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		reserved bool
	}{
		{name: "CGN start", ip: "100.64.0.0", reserved: true},
		{name: "CGN middle", ip: "100.100.100.100", reserved: true},
		{name: "CGN end", ip: "100.127.255.255", reserved: true},
		{name: "Not CGN - before", ip: "100.63.255.255", reserved: false},
		{name: "Not CGN - after", ip: "100.128.0.0", reserved: false},
		{name: "this-network reserved", ip: "0.1.2.3", reserved: true},
		{name: "IETF protocol assignments reserved", ip: "192.0.0.8", reserved: true},
		{name: "benchmarking reserved", ip: "198.18.0.1", reserved: true},
		{name: "TEST-NET-1", ip: "192.0.2.1", reserved: true},
		{name: "TEST-NET-2", ip: "198.51.100.1", reserved: true},
		{name: "TEST-NET-3", ip: "203.0.113.1", reserved: true},
		{name: "future-use IPv4 reserved", ip: "240.0.0.1", reserved: true},
		{name: "IPv6 doc prefix", ip: "2001:db8::1", reserved: true},
		{name: "IPv6 benchmarking prefix", ip: "2001:2::1", reserved: true},
		{name: "IPv6 ORCHIDv2 prefix", ip: "2001:20::1", reserved: true},
		{name: "IPv6 NAT64 well-known prefix", ip: "64:ff9b::808:808", reserved: true},
		{name: "IPv6 NAT64 local-use prefix", ip: "64:ff9b:1::1", reserved: true},
		{name: "IPv6 discard-only prefix", ip: "100::1", reserved: true},
		{name: "Not IPv6 doc - different prefix", ip: "2001:db9::1", reserved: false},
		{name: "Not ORCHIDv2 - outside prefix", ip: "2001:30::1", reserved: false},
		{name: "Public IPv4", ip: "8.8.8.8", reserved: false},
		{name: "Private IPv4", ip: "192.168.1.1", reserved: false},
		{name: "Public IPv6", ip: "2001:4860:4860::8888", reserved: false},
		{name: "IPv4-mapped reserved IPv6", ip: "::ffff:198.51.100.1", reserved: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isReservedIP(netip.MustParseAddr(tt.ip))
			if got != tt.reserved {
				t.Errorf("isReservedIP(%s) = %v, want %v", tt.ip, got, tt.reserved)
			}
		})
	}
}

func TestEvaluateClientIPReservedRanges(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want clientIPDisposition
	}{
		{name: "CGN rejected", ip: "100.64.0.1", want: clientIPReserved},
		{name: "benchmarking range rejected", ip: "198.18.1.1", want: clientIPReserved},
		{name: "future-use IPv4 rejected", ip: "240.0.0.2", want: clientIPReserved},
		{name: "TEST-NET-1 rejected", ip: "192.0.2.1", want: clientIPReserved},
		{name: "TEST-NET-2 rejected", ip: "198.51.100.1", want: clientIPReserved},
		{name: "TEST-NET-3 rejected", ip: "203.0.113.1", want: clientIPReserved},
		{name: "IPv6 doc rejected", ip: "2001:db8::1", want: clientIPReserved},
		{name: "IPv6 benchmarking rejected", ip: "2001:2::1", want: clientIPReserved},
		{name: "IPv6 NAT64 well-known rejected", ip: "64:ff9b::808:808", want: clientIPReserved},
		{name: "Private allowed when configured", ip: "192.168.1.1", want: clientIPValid},
		{name: "Public allowed", ip: "8.8.8.8", want: clientIPValid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateClientIP(netip.MustParseAddr(tt.ip), clientIPPolicy{AllowPrivateIPs: true})
			if got != tt.want {
				t.Errorf("evaluateClientIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestEvaluateClientIPWithAllowedReservedClientPrefixes(t *testing.T) {
	policy := clientIPPolicy{AllowReservedClientPrefixes: []netip.Prefix{netip.MustParsePrefix("100.64.0.0/10"), netip.MustParsePrefix("2001:db8::/32")}}

	tests := []struct {
		name string
		ip   string
		want clientIPDisposition
	}{
		{name: "allowlisted reserved IPv4", ip: "100.64.0.1", want: clientIPValid},
		{name: "non-allowlisted reserved IPv4", ip: "198.51.100.1", want: clientIPReserved},
		{name: "allowlisted reserved IPv6", ip: "2001:db8::1", want: clientIPValid},
		{name: "non-allowlisted reserved IPv6", ip: "64:ff9b::808:808", want: clientIPReserved},
		{name: "private remains rejected", ip: "192.168.1.1", want: clientIPPrivate},
		{name: "public remains allowed", ip: "8.8.8.8", want: clientIPValid},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateClientIP(netip.MustParseAddr(tt.ip), policy)
			if got != tt.want {
				t.Errorf("evaluateClientIP(%s) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

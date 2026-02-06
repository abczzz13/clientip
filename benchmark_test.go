package clientip

import (
	"net/http"
	"net/netip"
	"testing"
)

func BenchmarkExtractIP_RemoteAddr(b *testing.B) {
	extractor, _ := New()
	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractIP_XForwardedFor_Simple(b *testing.B) {
	extractor, _ := New()
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractIP_XForwardedFor_WithTrustedProxies(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, _ := New(
		TrustedProxies(cidrs, 1, 2),
	)
	req := &http.Request{
		RemoteAddr: "10.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractIP_XForwardedFor_LongChain(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, _ := New(
		TrustedProxies(cidrs, 1, 5),
	)
	req := &http.Request{
		RemoteAddr: "10.0.0.5:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8, 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractIP_WithDebugInfo(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, _ := New(
		TrustedProxies(cidrs, 1, 2),
		WithDebugInfo(true),
	)
	req := &http.Request{
		RemoteAddr: "10.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
		if result.DebugInfo == nil {
			b.Fatal("debug info missing")
		}
	}
}

func BenchmarkExtractIP_LeftmostStrategy(b *testing.B) {
	cidrs, _ := ParseCIDRs("173.245.48.0/20")
	extractor, _ := New(
		TrustedProxies(cidrs, 1, 3),
		XFFStrategy(LeftmostIP),
	)
	req := &http.Request{
		RemoteAddr: "173.245.48.5:443",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8, 173.245.48.5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractIP_CustomHeader(b *testing.B) {
	extractor, _ := New(
		Priority(
			"CF-Connecting-IP",
			SourceXForwardedFor,
			SourceRemoteAddr,
		),
	)
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result := extractor.ExtractIP(req)
		if !result.Valid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractIP_Parallel(b *testing.B) {
	extractor, _ := New()
	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := extractor.ExtractIP(req)
			if !result.Valid() {
				b.Fatal("extraction failed")
			}
		}
	})
}

func BenchmarkParseIP(b *testing.B) {
	testCases := []string{
		"1.1.1.1",
		"  1.1.1.1  ",
		"1.1.1.1:8080",
		"[2606:4700:4700::1]",
		"[2606:4700:4700::1]:8080",
		`"1.1.1.1"`,
	}

	for _, tc := range testCases {
		b.Run(tc, func(b *testing.B) {
			for i := 0; i < b.N; i++ {
				ip := parseIP(tc)
				if !ip.IsValid() {
					b.Fatal("parsing failed")
				}
			}
		})
	}
}

func BenchmarkParseCIDRs(b *testing.B) {
	cidrs := []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"2606:4700:4700::/32",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := ParseCIDRs(cidrs...)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkIsTrustedProxy(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
	extractor := &Extractor{
		config: &Config{
			trustedProxyCIDRs: cidrs,
		},
	}

	testIPs := []netip.Addr{
		netip.MustParseAddr("10.0.0.1"),
		netip.MustParseAddr("172.16.0.1"),
		netip.MustParseAddr("192.168.1.1"),
		netip.MustParseAddr("1.1.1.1"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, ip := range testIPs {
			extractor.isTrustedProxy(ip)
		}
	}
}

func BenchmarkChainAnalysis_Rightmost(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, _ := New(
		TrustedProxies(cidrs, 1, 3),
	)

	parts := []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "10.0.0.2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := extractor.analyzeChainRightmost(parts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkChainAnalysis_Leftmost(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	extractor, _ := New(
		TrustedProxies(cidrs, 1, 3),
		XFFStrategy(LeftmostIP),
	)

	parts := []string{"1.1.1.1", "8.8.8.8", "10.0.0.1", "10.0.0.2"}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := extractor.analyzeChainLeftmost(parts)
		if err != nil {
			b.Fatal(err)
		}
	}
}

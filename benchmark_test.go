package clientip

import (
	"context"
	"net/http"
	"testing"
)

func mustBenchmarkExtractor(b *testing.B, cfg Config) *Extractor {
	b.Helper()
	extractor, err := New(cfg)
	if err != nil {
		b.Fatalf("New() error = %v", err)
	}
	return extractor
}

func benchmarkExtractionLoop(b *testing.B, extract func() (Extraction, error)) {
	b.Helper()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extract()
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_RemoteAddr(b *testing.B) {
	extractor, _ := New(DefaultConfig())
	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_XForwardedFor_Simple(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_XForwardedFor_WithTrustedProxies(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 2
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "10.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_Forwarded_Simple(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceForwarded, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", "for=1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_Forwarded_WithParams(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceForwarded, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", `for="[2606:4700:4700::1]:8080";proto=https;by=10.0.0.1, for=1.1.1.1`)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_XForwardedFor_LongChain(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 5
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "10.0.0.5:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8, 10.0.0.1, 10.0.0.2, 10.0.0.3, 10.0.0.4, 10.0.0.5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_WithDebugInfo(b *testing.B) {
	cidrs, _ := ParseCIDRs("10.0.0.0/8")
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 2
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	cfg.DebugInfo = true
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "10.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
		if result.DebugInfo == nil {
			b.Fatal("debug info missing")
		}
	}
}

func BenchmarkExtract_LeftmostUntrustedSelection(b *testing.B) {
	cidrs, _ := ParseCIDRs("173.245.48.0/20")
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = cidrs
	cfg.MinTrustedProxies = 1
	cfg.MaxTrustedProxies = 3
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	cfg.ChainSelection = LeftmostUntrustedIP
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "173.245.48.5:443",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 8.8.8.8, 173.245.48.5")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_CustomHeader(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{HeaderSource("CF-Connecting-IP"), SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_Fallback_MissingPreferredHeader(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceXRealIP, SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.Extract(req)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_Parallel(b *testing.B) {
	extractor, _ := New(DefaultConfig())
	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result, err := extractor.Extract(req)
			if err != nil || !result.IP.IsValid() {
				b.Fatal("extraction failed")
			}
		}
	})
}

func BenchmarkExtractFrom_HTTP_RemoteAddr(b *testing.B) {
	extractor, _ := New(DefaultConfig())
	input := Input{
		Context:    context.Background(),
		RemoteAddr: "1.1.1.1:12345",
		Headers:    make(http.Header),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.ExtractInput(input)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractFrom_HTTP_XForwardedFor_Simple(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	headers := make(http.Header)
	headers.Set("X-Forwarded-For", "1.1.1.1")
	input := Input{
		Context:    context.Background(),
		RemoteAddr: "127.0.0.1:12345",
		Headers:    headers,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.ExtractInput(input)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtractFrom_HeaderValuesFunc_XForwardedFor_Simple(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	extractor, _ := New(cfg)
	xffValues := []string{"1.1.1.1"}
	input := Input{
		Context:    context.Background(),
		RemoteAddr: "127.0.0.1:12345",
		Headers: HeaderValuesFunc(func(name string) []string {
			if name == "X-Forwarded-For" {
				return xffValues
			}
			return nil
		}),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		result, err := extractor.ExtractInput(input)
		if err != nil || !result.IP.IsValid() {
			b.Fatal("extraction failed")
		}
	}
}

func BenchmarkExtract_RequestVsInput_RemoteAddr(b *testing.B) {
	extractor := mustBenchmarkExtractor(b, DefaultConfig())
	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}
	input := Input{Context: context.Background(), RemoteAddr: "1.1.1.1:12345"}

	b.Run("request", func(b *testing.B) {
		benchmarkExtractionLoop(b, func() (Extraction, error) { return extractor.Extract(req) })
	})

	b.Run("input", func(b *testing.B) {
		benchmarkExtractionLoop(b, func() (Extraction, error) { return extractor.ExtractInput(input) })
	})
}

func BenchmarkExtract_RequestVsInput_XForwardedFor(b *testing.B) {
	cfg := DefaultConfig()
	cfg.TrustedProxyPrefixes = LoopbackProxyPrefixes()
	cfg.Sources = []Source{SourceXForwardedFor, SourceRemoteAddr}
	extractor := mustBenchmarkExtractor(b, cfg)
	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")
	inputHTTP := Input{
		Context:    context.Background(),
		RemoteAddr: "127.0.0.1:12345",
		Headers:    http.Header{"X-Forwarded-For": {"1.1.1.1"}},
	}
	inputFunc := Input{
		Context:    context.Background(),
		RemoteAddr: "127.0.0.1:12345",
		Headers: HeaderValuesFunc(func(name string) []string {
			if name == "X-Forwarded-For" {
				return []string{"1.1.1.1"}
			}
			return nil
		}),
	}

	b.Run("request", func(b *testing.B) {
		benchmarkExtractionLoop(b, func() (Extraction, error) { return extractor.Extract(req) })
	})

	b.Run("input_http_header", func(b *testing.B) {
		benchmarkExtractionLoop(b, func() (Extraction, error) { return extractor.ExtractInput(inputHTTP) })
	})

	b.Run("input_header_func", func(b *testing.B) {
		benchmarkExtractionLoop(b, func() (Extraction, error) { return extractor.ExtractInput(inputFunc) })
	})
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

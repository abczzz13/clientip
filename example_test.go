package clientip_test

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"

	"github.com/abczzz13/clientip"
)

func ExampleResolver_ResolveStrict() {
	extractor, err := clientip.New(clientip.PresetLoopbackReverseProxy())
	if err != nil {
		panic(err)
	}

	resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	req, resolution := resolver.ResolveStrict(req)
	if resolution.Err != nil {
		panic(resolution.Err)
	}

	fmt.Println(resolution.IP, resolution.Source, resolution.FallbackUsed)

	cached, ok := clientip.StrictResolutionFromContext(req.Context())
	fmt.Println(ok, cached.IP)
	// Output:
	// 8.8.8.8 x_forwarded_for false
	// true 8.8.8.8
}

func ExampleResolver_ResolvePreferred() {
	extractor, err := clientip.New(clientip.Config{
		TrustedProxyPrefixes: clientip.LoopbackProxyPrefixes(),
		Sources:              []clientip.Source{clientip.SourceXForwardedFor},
	})
	if err != nil {
		panic(err)
	}

	resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{PreferredFallback: clientip.PreferredFallbackRemoteAddr})
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}

	_, resolution := resolver.ResolvePreferred(req)
	if resolution.Err != nil {
		panic(resolution.Err)
	}

	fmt.Println(resolution.IP, resolution.Source, resolution.FallbackUsed)
	// Output:
	// 1.1.1.1 remote_addr true
}

func ExamplePreferredResolutionFromContext() {
	extractor, err := clientip.New(clientip.DefaultConfig())
	if err != nil {
		panic(err)
	}

	resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "8.8.4.4:12345", Header: make(http.Header)}

	req, resolution := resolver.ResolvePreferred(req)
	if resolution.Err != nil {
		panic(resolution.Err)
	}

	cached, ok := clientip.PreferredResolutionFromContext(req.Context())
	fmt.Println(ok, cached.IP == resolution.IP, cached.Source)
	// Output:
	// true true remote_addr
}

func ExampleExtractor_Extract() {
	extractor, err := clientip.New(clientip.DefaultConfig())
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "8.8.4.4:12345", Header: make(http.Header)}

	extraction, err := extractor.Extract(req)
	if err != nil {
		panic(err)
	}

	fmt.Println(extraction.IP, extraction.Source)
	// Output:
	// 8.8.4.4 remote_addr
}

func ExamplePresetVMReverseProxy() {
	extractor, err := clientip.New(clientip.PresetVMReverseProxy())
	if err != nil {
		panic(err)
	}

	resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	_, resolution := resolver.ResolveStrict(req)
	if resolution.Err != nil {
		panic(resolution.Err)
	}

	fmt.Println(resolution.IP, resolution.Source)
	// Output: 1.1.1.1 x_forwarded_for
}

func ExampleResolver_ResolveInputPreferred() {
	extractor, err := clientip.New(clientip.Config{
		TrustedProxyPrefixes: clientip.LoopbackProxyPrefixes(),
		Sources:              []clientip.Source{clientip.HeaderSource("CF-Connecting-IP"), clientip.SourceRemoteAddr},
	})
	if err != nil {
		panic(err)
	}

	resolver, err := clientip.NewResolver(extractor, clientip.ResolverConfig{})
	if err != nil {
		panic(err)
	}

	cfHeader := textproto.CanonicalMIMEHeaderKey("CF-Connecting-IP")
	input := clientip.Input{
		Context:    context.Background(),
		RemoteAddr: "127.0.0.1:12345",
		Path:       "/framework-request",
		Headers: clientip.HeaderValuesFunc(func(name string) []string {
			if name == cfHeader {
				return []string{"8.8.8.8"}
			}
			return nil
		}),
	}

	input, resolution := resolver.ResolveInputPreferred(input)
	if resolution.Err != nil {
		panic(resolution.Err)
	}

	cached, ok := clientip.PreferredResolutionFromContext(input.Context)
	fmt.Println(resolution.IP, resolution.Source, resolution.FallbackUsed)
	fmt.Println(ok, cached.Source)
	// Output:
	// 8.8.8.8 cf_connecting_ip false
	// true cf_connecting_ip
}

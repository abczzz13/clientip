package clientip_test

import (
	"context"
	"fmt"
	"net/http"
	"net/textproto"

	"github.com/abczzz13/clientip"
)

func ExampleResolver_Resolve() {
	resolver, err := clientip.New(clientip.PresetLoopbackReverseProxy())
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	result := resolver.Resolve(req)
	if result.Err != nil {
		panic(result.Err)
	}

	fmt.Println(result.IP, result.Source, result.FallbackUsed)
	// Output: 8.8.8.8 x_forwarded_for false
}

func ExampleResolver_ResolveOperational() {
	resolver, err := clientip.New(
		clientip.WithTrustedProxies(clientip.LoopbackProxyPrefixes()...),
		clientip.WithSources(clientip.SourceXForwardedFor),
	)
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}

	result := resolver.ResolveOperational(req, clientip.RemoteAddrFallback())
	if result.Err != nil {
		panic(result.Err)
	}

	fmt.Println(result.IP, result.Source, result.FallbackUsed)
	// Output: 1.1.1.1 remote_addr true
}

func ExampleResolver_Middleware() {
	resolver, err := clientip.New()
	if err != nil {
		panic(err)
	}

	handler := resolver.Middleware()(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		result, ok := clientip.FromContext(r.Context())
		fmt.Println(ok, result.IP, result.Source)
	}))

	req := &http.Request{RemoteAddr: "8.8.4.4:12345", Header: make(http.Header)}
	handler.ServeHTTP(noopResponseWriter{}, req)
	// Output: true 8.8.4.4 remote_addr
}

func ExamplePresetVMReverseProxy() {
	resolver, err := clientip.New(clientip.PresetVMReverseProxy())
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result := resolver.Resolve(req)
	if result.Err != nil {
		panic(result.Err)
	}

	fmt.Println(result.IP, result.Source)
	// Output: 1.1.1.1 x_forwarded_for
}

func ExampleResolver_ResolveInput() {
	resolver, err := clientip.New(
		clientip.WithTrustedProxies(clientip.LoopbackProxyPrefixes()...),
		clientip.WithSources(clientip.HeaderSource("CF-Connecting-IP"), clientip.SourceRemoteAddr),
	)
	if err != nil {
		panic(err)
	}

	cfHeader := textproto.CanonicalMIMEHeaderKey("CF-Connecting-IP")
	input := clientip.Input{
		Context:    context.Background(),
		RemoteAddr: "127.0.0.1:12345",
		Headers: clientip.HeaderValuesFunc(func(name string) []string {
			if name == cfHeader {
				return []string{"8.8.8.8"}
			}
			return nil
		}),
	}

	result := resolver.ResolveInput(input)
	if result.Err != nil {
		panic(result.Err)
	}

	fmt.Println(result.IP, result.Source, result.FallbackUsed)
	// Output: 8.8.8.8 cf_connecting_ip false
}

type noopResponseWriter struct{}

func (noopResponseWriter) Header() http.Header       { return http.Header{} }
func (noopResponseWriter) Write([]byte) (int, error) { return 0, nil }
func (noopResponseWriter) WriteHeader(int)           {}

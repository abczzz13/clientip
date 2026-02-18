package clientip_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"net/textproto"
	"os"

	"github.com/abczzz13/clientip"
)

func ExampleNew_simple() {
	extractor, err := clientip.New()
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "8.8.4.4:12345", Header: make(http.Header)}

	ip, err := extractor.ExtractAddr(req)
	if err != nil {
		panic(err)
	}

	fmt.Printf("Client IP: %s\n", ip)
}

func ExamplePresetVMReverseProxy() {
	extractor, _ := clientip.New(clientip.PresetVMReverseProxy())

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	extraction, _ := extractor.Extract(req)
	fmt.Println(extraction.IP, extraction.Source)
	// Output: 1.1.1.1 x_forwarded_for
}

func ExamplePresetPreferredHeaderThenXFFLax() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.PresetPreferredHeaderThenXFFLax("X-Frontend-IP"),
	)

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Frontend-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	extraction, _ := extractor.Extract(req)
	fmt.Println(extraction.IP, extraction.Source)
	// Output: 8.8.8.8 x_forwarded_for
}

func ExampleNew_forwarded() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority(clientip.SourceForwarded, clientip.SourceRemoteAddr),
	)

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("Forwarded", "for=1.1.1.1")

	extraction, _ := extractor.Extract(req)
	fmt.Println(extraction.IP, extraction.Source)
	// Output: 1.1.1.1 forwarded
}

func ExampleNew_withOptions() {
	cidrs, _ := netip.ParsePrefix("10.0.0.0/8")

	extractor, err := clientip.New(
		clientip.TrustProxyPrefixes(cidrs),
		clientip.MinTrustedProxies(1),
		clientip.MaxTrustedProxies(2),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
		clientip.AllowPrivateIPs(false),
		clientip.WithLogger(slog.New(slog.NewTextHandler(os.Stdout, nil))),
	)
	if err != nil {
		panic(err)
	}

	req := &http.Request{RemoteAddr: "10.0.1.5:12345", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.1.5")

	extraction, _ := extractor.Extract(req)
	fmt.Printf("Client IP: %s from source: %s\n", extraction.IP, extraction.Source)
}

func ExampleAllowReservedClientPrefixes() {
	extractor, _ := clientip.New(
		clientip.AllowReservedClientPrefixes(netip.MustParsePrefix("198.51.100.0/24")),
	)

	req := &http.Request{RemoteAddr: "198.51.100.10:12345", Header: make(http.Header)}

	extraction, _ := extractor.Extract(req)
	fmt.Println(extraction.IP, extraction.Source)
	// Output: 198.51.100.10 remote_addr
}

func ExampleNew_flexibleProxyRange() {
	cidrs, _ := netip.ParsePrefix("10.0.0.0/8")

	extractor, _ := clientip.New(
		clientip.TrustProxyPrefixes(cidrs),
		clientip.MinTrustedProxies(1),
		clientip.MaxTrustedProxies(3),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
	)

	req1 := &http.Request{RemoteAddr: "10.0.0.1:12345", Header: make(http.Header)}
	req1.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")
	extraction1, _ := extractor.Extract(req1)
	fmt.Printf("1 proxy: %s\n", extraction1.IP)

	req2 := &http.Request{RemoteAddr: "10.0.0.3:12345", Header: make(http.Header)}
	req2.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.2, 10.0.0.3")
	extraction2, _ := extractor.Extract(req2)
	fmt.Printf("2 proxies: %s\n", extraction2.IP)
}

func ExampleNew_cloudflare() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority("CF-Connecting-IP", clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
	)

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")

	extraction, _ := extractor.Extract(req)
	fmt.Printf("Client IP: %s (from %s)\n", extraction.IP, extraction.Source)
}

func ExampleHeader() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority("X-Custom-IP", clientip.SourceRemoteAddr),
	)

	req := &http.Request{RemoteAddr: "127.0.0.1:12345", Header: make(http.Header)}
	req.Header.Set("X-Custom-IP", "8.8.8.8")

	ip, _ := extractor.ExtractAddr(req)
	fmt.Printf("IP: %s\n", ip)
}

func ExampleWithChainSelection_leftmostUntrusted() {
	cloudflareCIDRs, _ := netip.ParsePrefix("173.245.48.0/20")

	extractor, _ := clientip.New(
		clientip.TrustProxyPrefixes(cloudflareCIDRs),
		clientip.MinTrustedProxies(1),
		clientip.MaxTrustedProxies(3),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
		clientip.WithChainSelection(clientip.LeftmostUntrustedIP),
	)

	req := &http.Request{RemoteAddr: "173.245.48.5:443", Header: make(http.Header)}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 173.245.48.5")

	ip, _ := extractor.ExtractAddr(req)
	fmt.Printf("Client IP: %s\n", ip)
}

func ExampleWithSecurityMode_strict() {
	extractor, _ := clientip.New(
		clientip.TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		clientip.Priority(clientip.SourceForwarded, clientip.SourceRemoteAddr),
		clientip.WithSecurityMode(clientip.SecurityModeStrict),
	)

	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}
	req.Header.Set("Forwarded", `for="1.1.1.1`)

	extraction, err := extractor.Extract(req)
	fmt.Println(err == nil, errors.Is(err, clientip.ErrInvalidForwardedHeader), extraction.Source)
	// Output: false true forwarded
}

func ExampleWithSecurityMode_lax() {
	extractor, _ := clientip.New(
		clientip.TrustProxyAddrs(netip.MustParseAddr("1.1.1.1")),
		clientip.Priority(clientip.SourceForwarded, clientip.SourceRemoteAddr),
		clientip.WithSecurityMode(clientip.SecurityModeLax),
	)

	req := &http.Request{RemoteAddr: "1.1.1.1:12345", Header: make(http.Header)}
	req.Header.Set("Forwarded", `for="1.1.1.1`)

	extraction, _ := extractor.Extract(req)
	fmt.Println(extraction.IP, extraction.Source)
	// Output: 1.1.1.1 remote_addr
}

func ExampleExtractor_ExtractFrom() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority("CF-Connecting-IP", clientip.SourceRemoteAddr),
	)

	cfHeader := textproto.CanonicalMIMEHeaderKey("CF-Connecting-IP")
	input := clientip.RequestInput{
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

	extraction, _ := extractor.ExtractFrom(input)
	fmt.Println(extraction.IP, extraction.Source)
	// Output: 8.8.8.8 cf_connecting_ip
}

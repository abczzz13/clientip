package clientip_test

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"os"

	"github.com/abczzz13/clientip"
)

func ExampleNew_simple() {
	extractor, err := clientip.New()
	if err != nil {
		panic(err)
	}

	req := &http.Request{
		RemoteAddr: "8.8.4.4:12345",
		Header:     make(http.Header),
	}

	result := extractor.ExtractIP(req)
	if result.Valid() {
		fmt.Printf("Client IP: %s\n", result.IP)
	}
}

func ExamplePresetVMReverseProxy() {
	extractor, _ := clientip.New(
		clientip.PresetVMReverseProxy(),
	)

	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1")

	result := extractor.ExtractIP(req)
	fmt.Println(result.IP, result.Source)
	// Output: 1.1.1.1 x_forwarded_for
}

func ExamplePresetPreferredHeaderThenXFFLax() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.PresetPreferredHeaderThenXFFLax("X-Frontend-IP"),
	)

	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Frontend-IP", "not-an-ip")
	req.Header.Set("X-Forwarded-For", "8.8.8.8")

	result := extractor.ExtractIP(req)
	fmt.Println(result.IP, result.Source)
	// Output: 8.8.8.8 x_forwarded_for
}

func ExampleNew_forwarded() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority(clientip.SourceForwarded, clientip.SourceRemoteAddr),
	)

	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("Forwarded", "for=1.1.1.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		fmt.Println(result.IP, result.Source)
	}
	// Output: 1.1.1.1 forwarded
}

func ExampleNew_withOptions() {
	cidrs, _ := netip.ParsePrefix("10.0.0.0/8")

	extractor, err := clientip.New(
		clientip.TrustedProxies([]netip.Prefix{cidrs}, 1, 2),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
		clientip.AllowPrivateIPs(false),
		clientip.WithLogger(slog.New(slog.NewTextHandler(os.Stdout, nil))),
	)
	if err != nil {
		panic(err)
	}

	req := &http.Request{
		RemoteAddr: "10.0.1.5:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.1.5")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		fmt.Printf("Client IP: %s from source: %s\n", result.IP, result.Source)
	}
}

func ExampleNew_flexibleProxyRange() {
	cidrs, _ := netip.ParsePrefix("10.0.0.0/8")

	extractor, _ := clientip.New(
		clientip.TrustedProxies([]netip.Prefix{cidrs}, 1, 3),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
	)

	req1 := &http.Request{
		RemoteAddr: "10.0.0.1:12345",
		Header:     make(http.Header),
	}
	req1.Header.Set("X-Forwarded-For", "1.1.1.1, 10.0.0.1")
	result1 := extractor.ExtractIP(req1)
	fmt.Printf("1 proxy: %s\n", result1.IP)

	req2 := &http.Request{
		RemoteAddr: "10.0.0.3:12345",
		Header:     make(http.Header),
	}
	req2.Header.Set("X-Forwarded-For", "8.8.8.8, 10.0.0.2, 10.0.0.3")
	result2 := extractor.ExtractIP(req2)
	fmt.Printf("2 proxies: %s\n", result2.IP)
}

func ExampleNew_cloudflare() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority(
			"CF-Connecting-IP",
			clientip.SourceXForwardedFor,
			clientip.SourceRemoteAddr,
		),
	)

	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("CF-Connecting-IP", "1.1.1.1")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		fmt.Printf("Client IP: %s (from %s)\n", result.IP, result.Source)
	}
}

func ExampleHeader() {
	extractor, _ := clientip.New(
		clientip.TrustLoopbackProxy(),
		clientip.Priority(
			"X-Custom-IP",
			clientip.SourceRemoteAddr,
		),
	)

	req := &http.Request{
		RemoteAddr: "127.0.0.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Custom-IP", "8.8.8.8")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		fmt.Printf("IP: %s\n", result.IP)
	}
}

func ExampleWithChainSelection_leftmostUntrusted() {
	cloudflareCIDRs, _ := netip.ParsePrefix("173.245.48.0/20")

	extractor, _ := clientip.New(
		clientip.TrustedProxies([]netip.Prefix{cloudflareCIDRs}, 1, 3),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
		clientip.WithChainSelection(clientip.LeftmostUntrustedIP),
	)

	req := &http.Request{
		RemoteAddr: "173.245.48.5:443",
		Header:     make(http.Header),
	}
	req.Header.Set("X-Forwarded-For", "1.1.1.1, 173.245.48.5")

	result := extractor.ExtractIP(req)
	if result.Valid() {
		fmt.Printf("Client IP: %s\n", result.IP)
	}
}

func ExampleWithSecurityMode_strict() {
	extractor, _ := clientip.New(
		clientip.TrustProxyIP("1.1.1.1"),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
		clientip.WithSecurityMode(clientip.SecurityModeStrict),
	)

	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "9.9.9.9")

	result := extractor.ExtractIP(req)
	fmt.Println(result.Valid(), errors.Is(result.Err, clientip.ErrMultipleXFFHeaders), result.Source)
	// Output: false true x_forwarded_for
}

func ExampleWithSecurityMode_lax() {
	extractor, _ := clientip.New(
		clientip.TrustProxyIP("1.1.1.1"),
		clientip.Priority(clientip.SourceXForwardedFor, clientip.SourceRemoteAddr),
		clientip.WithSecurityMode(clientip.SecurityModeLax),
	)

	req := &http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	}
	req.Header.Add("X-Forwarded-For", "8.8.8.8")
	req.Header.Add("X-Forwarded-For", "9.9.9.9")

	result := extractor.ExtractIP(req)
	fmt.Println(result.IP, result.Source)
	// Output: 1.1.1.1 remote_addr
}

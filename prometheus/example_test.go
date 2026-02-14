package prometheus_test

import (
	"fmt"
	"net/http"

	"github.com/abczzz13/clientip"
	clientipprom "github.com/abczzz13/clientip/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
)

func ExampleWithMetrics() {
	extractor, err := clientip.New(clientipprom.WithMetrics())
	if err != nil {
		panic(err)
	}

	result, err := extractor.Extract(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(result.IP, result.Source)
	// Output: 1.1.1.1 remote_addr
}

func ExampleWithRegisterer() {
	registry := prom.NewRegistry()

	extractor, err := clientip.New(clientipprom.WithRegisterer(registry))
	if err != nil {
		panic(err)
	}

	_, err = extractor.Extract(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%.0f\n", counterValue(registry, "ip_extraction_total", map[string]string{
		"source": clientip.SourceRemoteAddr,
		"result": "success",
	}))
	// Output: 1
}

func ExampleNew() {
	metrics, err := clientipprom.New()
	if err != nil {
		panic(err)
	}

	extractor, err := clientip.New(clientip.WithMetrics(metrics))
	if err != nil {
		panic(err)
	}

	result, err := extractor.Extract(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})
	if err != nil {
		panic(err)
	}

	fmt.Println(result.IP, result.Source)
	// Output: 1.1.1.1 remote_addr
}

func ExampleNewWithRegisterer() {
	registry := prom.NewRegistry()

	metrics, err := clientipprom.NewWithRegisterer(registry)
	if err != nil {
		panic(err)
	}

	extractor, err := clientip.New(clientip.WithMetrics(metrics))
	if err != nil {
		panic(err)
	}

	_, err = extractor.Extract(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})
	if err != nil {
		panic(err)
	}

	fmt.Printf("%.0f\n", counterValue(registry, "ip_extraction_total", map[string]string{
		"source": clientip.SourceRemoteAddr,
		"result": "success",
	}))
	// Output: 1
}

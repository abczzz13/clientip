package prometheus_test

import (
	"fmt"
	"net/http"

	"github.com/abczzz13/clientip"
	clientipprom "github.com/abczzz13/clientip/observe/prometheus"
	prom "github.com/prometheus/client_golang/prometheus"
)

func counterValue(registry *prom.Registry, metricName string, labels map[string]string) float64 {
	value, found, err := lookupCounterValue(registry, metricName, labels)
	if err != nil {
		panic(err)
	}
	if !found {
		panic(fmt.Sprintf("counter %q with labels %v not found", metricName, labels))
	}
	return value
}

func ExampleNew() {
	metrics, err := clientipprom.New()
	if err != nil {
		panic(err)
	}

	resolver, err := clientip.New(clientip.WithObserver(metrics))
	if err != nil {
		panic(err)
	}

	result := resolver.Resolve(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})
	if result.Err != nil {
		panic(result.Err)
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

	resolver, err := clientip.New(clientip.WithObserver(metrics))
	if err != nil {
		panic(err)
	}

	result := resolver.Resolve(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})
	if result.Err != nil {
		panic(result.Err)
	}

	fmt.Printf("%.0f\n", counterValue(registry, "ip_resolution_total", map[string]string{
		"source": clientip.SourceRemoteAddr.String(),
		"result": clientip.ResultSuccess.String(),
	}))
	// Output: 1
}

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

	result := extractor.ExtractIP(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})

	fmt.Println(result.IP, result.Source)
	// Output: 1.1.1.1 remote_addr
}

func ExampleWithRegisterer() {
	registry := prom.NewRegistry()

	extractor, err := clientip.New(clientipprom.WithRegisterer(registry))
	if err != nil {
		panic(err)
	}

	extractor.ExtractIP(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})

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

	result := extractor.ExtractIP(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})

	fmt.Println(result.Valid())
	// Output: true
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

	extractor.ExtractIP(&http.Request{
		RemoteAddr: "1.1.1.1:12345",
		Header:     make(http.Header),
	})

	fmt.Printf("%.0f\n", counterValue(registry, "ip_extraction_total", map[string]string{
		"source": clientip.SourceRemoteAddr,
		"result": "success",
	}))
	// Output: 1
}

func counterValue(registry *prom.Registry, metricName string, labels map[string]string) float64 {
	metricFamilies, err := registry.Gather()
	if err != nil {
		return 0
	}

	for _, family := range metricFamilies {
		if family.GetName() != metricName {
			continue
		}

		for _, metric := range family.GetMetric() {
			if metric.GetCounter() == nil {
				continue
			}

			actual := make(map[string]string, len(metric.GetLabel()))
			for _, pair := range metric.GetLabel() {
				actual[pair.GetName()] = pair.GetValue()
			}

			matched := true
			for labelName, labelValue := range labels {
				if actual[labelName] != labelValue {
					matched = false
					break
				}
			}
			if !matched {
				continue
			}

			return metric.GetCounter().GetValue()
		}
	}

	return 0
}

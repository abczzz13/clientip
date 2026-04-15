package clientip

import (
	"net/http"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
)

type trackingHeaderProvider struct {
	values map[string][]string
	calls  []string
}

func (p *trackingHeaderProvider) Values(name string) []string {
	p.calls = append(p.calls, name)
	return p.values[name]
}

type panicIfCalledHeaderProvider struct{}

func (p *panicIfCalledHeaderProvider) Values(string) []string {
	if p == nil {
		panic("typed nil header provider should not be called")
	}

	return nil
}

func TestRequestFromInput_HeaderProviderPaths(t *testing.T) {
	var nilHTTPHeader *http.Header
	var nilHeaderFunc HeaderValuesFunc
	var nilCustomProvider *panicIfCalledHeaderProvider

	tests := []struct {
		name              string
		sourceHeaderKeys  []string
		newInput          func(t *testing.T) (RequestInput, func() []string)
		wantRemoteAddr    string
		wantPath          string
		wantHeaders       http.Header
		wantProviderCalls []string
	}{
		{
			name:             "nil headers treated as absent",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				return RequestInput{RemoteAddr: "8.8.8.8:443", Path: "/nil-headers"}, nil
			},
			wantRemoteAddr: "8.8.8.8:443",
			wantPath:       "/nil-headers",
		},
		{
			name:             "http.Header passthrough",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				return RequestInput{
					RemoteAddr: "1.1.1.1:80",
					Path:       "/http-header",
					Headers: http.Header{
						"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
						"X-Real-IP":       {"4.4.4.4"},
					},
				}, nil
			},
			wantRemoteAddr: "1.1.1.1:80",
			wantPath:       "/http-header",
			wantHeaders: http.Header{
				"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
				"X-Real-IP":       {"4.4.4.4"},
			},
		},
		{
			name:             "*http.Header passthrough",
			sourceHeaderKeys: []string{"Forwarded"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				h := http.Header{"Forwarded": {"for=1.1.1.1"}}
				return RequestInput{RemoteAddr: "2.2.2.2:80", Path: "/header-pointer", Headers: &h}, nil
			},
			wantRemoteAddr: "2.2.2.2:80",
			wantPath:       "/header-pointer",
			wantHeaders:    http.Header{"Forwarded": {"for=1.1.1.1"}},
		},
		{
			name:             "typed nil *http.Header treated as absent",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				return RequestInput{
					RemoteAddr: "3.3.3.3:80",
					Path:       "/typed-nil-header",
					Headers:    nilHTTPHeader,
				}, nil
			},
			wantRemoteAddr: "3.3.3.3:80",
			wantPath:       "/typed-nil-header",
		},
		{
			name:             "nil HeaderValuesFunc treated as absent",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				return RequestInput{
					RemoteAddr: "4.4.4.4:80",
					Path:       "/nil-header-func",
					Headers:    nilHeaderFunc,
				}, nil
			},
			wantRemoteAddr: "4.4.4.4:80",
			wantPath:       "/nil-header-func",
		},
		{
			name:             "single-key provider path",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				provider := &trackingHeaderProvider{
					values: map[string][]string{
						"X-Forwarded-For": {"8.8.8.8"},
						"X-Real-IP":       {"7.7.7.7"},
					},
				}
				return RequestInput{RemoteAddr: "5.5.5.5:80", Path: "/single-key", Headers: provider}, func() []string {
					return provider.calls
				}
			},
			wantRemoteAddr:    "5.5.5.5:80",
			wantPath:          "/single-key",
			wantHeaders:       http.Header{"X-Forwarded-For": {"8.8.8.8"}},
			wantProviderCalls: []string{"X-Forwarded-For"},
		},
		{
			name:             "multiple-key provider path",
			sourceHeaderKeys: []string{"Forwarded", "X-Forwarded-For", "X-Real-IP"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				provider := &trackingHeaderProvider{
					values: map[string][]string{
						"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
						"X-Real-IP":       {"7.7.7.7"},
					},
				}
				return RequestInput{RemoteAddr: "6.6.6.6:80", Path: "/multiple-keys", Headers: provider}, func() []string {
					return provider.calls
				}
			},
			wantRemoteAddr: "6.6.6.6:80",
			wantPath:       "/multiple-keys",
			wantHeaders: http.Header{
				"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
				"X-Real-IP":       {"7.7.7.7"},
			},
			wantProviderCalls: []string{"Forwarded", "X-Forwarded-For", "X-Real-IP"},
		},
		{
			name:             "HeaderValuesFunc provider path",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				calls := make([]string, 0, 1)
				headers := HeaderValuesFunc(func(name string) []string {
					calls = append(calls, name)
					if name == "X-Forwarded-For" {
						return []string{"8.8.8.8"}
					}
					return nil
				})
				return RequestInput{RemoteAddr: "6.6.6.7:80", Path: "/header-func", Headers: headers}, func() []string {
					return calls
				}
			},
			wantRemoteAddr:    "6.6.6.7:80",
			wantPath:          "/header-func",
			wantHeaders:       http.Header{"X-Forwarded-For": {"8.8.8.8"}},
			wantProviderCalls: []string{"X-Forwarded-For"},
		},
		{
			name:             "no source keys skips provider",
			sourceHeaderKeys: nil,
			newInput: func(t *testing.T) (RequestInput, func() []string) {
				calls := make([]string, 0, 1)
				headers := HeaderValuesFunc(func(name string) []string {
					calls = append(calls, name)
					t.Fatalf("header provider should not be called when sourceHeaderKeys is empty (called with %q)", name)
					return nil
				})
				return RequestInput{RemoteAddr: "7.7.7.7:80", Path: "/skip-provider", Headers: headers}, func() []string {
					return calls
				}
			},
			wantRemoteAddr:    "7.7.7.7:80",
			wantPath:          "/skip-provider",
			wantProviderCalls: []string{},
		},
		{
			name:             "typed nil custom provider treated as absent",
			sourceHeaderKeys: []string{"X-Forwarded-For"},
			newInput: func(*testing.T) (RequestInput, func() []string) {
				return RequestInput{
					RemoteAddr: "9.9.9.9:80",
					Path:       "/typed-nil-provider",
					Headers:    nilCustomProvider,
				}, nil
			},
			wantRemoteAddr: "9.9.9.9:80",
			wantPath:       "/typed-nil-provider",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input, providerCalls := tt.newInput(t)
			req := requestFromInput(input, tt.sourceHeaderKeys)

			got := struct {
				RemoteAddr string
				Path       string
				Headers    http.Header
			}{
				RemoteAddr: req.RemoteAddr,
				Headers:    req.Header,
			}
			if req.URL != nil {
				got.Path = req.URL.Path
			}

			want := struct {
				RemoteAddr string
				Path       string
				Headers    http.Header
			}{
				RemoteAddr: tt.wantRemoteAddr,
				Path:       tt.wantPath,
				Headers:    tt.wantHeaders,
			}

			if diff := cmp.Diff(want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("request mismatch (-want +got):\n%s", diff)
			}

			if providerCalls == nil {
				return
			}

			if diff := cmp.Diff(tt.wantProviderCalls, providerCalls(), cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("provider calls mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSourceHeaderKeys_DedupesAndCanonicalizes(t *testing.T) {
	tests := []struct {
		name           string
		sourcePriority []string
		want           []string
	}{
		{
			name:           "remote addr only",
			sourcePriority: []string{SourceRemoteAddr},
		},
		{
			name:           "built-in chain header",
			sourcePriority: []string{SourceXForwardedFor, SourceRemoteAddr},
			want:           []string{"X-Forwarded-For"},
		},
		{
			name:           "duplicate built-in alias",
			sourcePriority: []string{SourceXForwardedFor, "X-Forwarded-For"},
			want:           []string{"X-Forwarded-For"},
		},
		{
			name:           "mixed built-in and custom headers",
			sourcePriority: []string{SourceForwarded, SourceXRealIP, "cf-connecting-ip"},
			want:           []string{"Forwarded", "X-Real-IP", "Cf-Connecting-Ip"},
		},
		{
			name:           "duplicate custom header in different cases",
			sourcePriority: []string{"CF-Connecting-IP", "cf-connecting-ip", "Cf-Connecting-Ip"},
			want:           []string{"Cf-Connecting-Ip"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sourceHeaderKeys(tt.sourcePriority)
			if diff := cmp.Diff(tt.want, got, cmpopts.EquateEmpty()); diff != "" {
				t.Fatalf("sourceHeaderKeys() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

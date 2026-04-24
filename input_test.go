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

func TestRequestViewFromInput_HeaderProviderPaths(t *testing.T) {
	var nilHTTPHeader *http.Header
	var nilHeaderFunc HeaderValuesFunc
	var nilCustomProvider *panicIfCalledHeaderProvider

	tests := []struct {
		name              string
		headerName        string
		newInput          func(t *testing.T) (Input, func() []string)
		wantRemoteAddr    string
		wantPath          string
		wantHeaderValues  []string
		wantProviderCalls []string
	}{
		{
			name:       "nil headers treated as absent",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				return Input{RemoteAddr: "8.8.8.8:443", Path: "/nil-headers"}, nil
			},
			wantRemoteAddr: "8.8.8.8:443",
			wantPath:       "/nil-headers",
		},
		{
			name:       "http.Header passthrough",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				return Input{
					RemoteAddr: "1.1.1.1:80",
					Path:       "/http-header",
					Headers: http.Header{
						"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
						"X-Real-IP":       {"4.4.4.4"},
					},
				}, nil
			},
			wantRemoteAddr:   "1.1.1.1:80",
			wantPath:         "/http-header",
			wantHeaderValues: []string{"8.8.8.8", "9.9.9.9"},
		},
		{
			name:       "*http.Header passthrough",
			headerName: "Forwarded",
			newInput: func(*testing.T) (Input, func() []string) {
				h := http.Header{"Forwarded": {"for=1.1.1.1"}}
				return Input{RemoteAddr: "2.2.2.2:80", Path: "/header-pointer", Headers: &h}, nil
			},
			wantRemoteAddr:   "2.2.2.2:80",
			wantPath:         "/header-pointer",
			wantHeaderValues: []string{"for=1.1.1.1"},
		},
		{
			name:       "typed nil *http.Header treated as absent",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				return Input{
					RemoteAddr: "3.3.3.3:80",
					Path:       "/typed-nil-header",
					Headers:    nilHTTPHeader,
				}, nil
			},
			wantRemoteAddr: "3.3.3.3:80",
			wantPath:       "/typed-nil-header",
		},
		{
			name:       "nil HeaderValuesFunc treated as absent",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				return Input{
					RemoteAddr: "4.4.4.4:80",
					Path:       "/nil-header-func",
					Headers:    nilHeaderFunc,
				}, nil
			},
			wantRemoteAddr: "4.4.4.4:80",
			wantPath:       "/nil-header-func",
		},
		{
			name:       "provider path forwards header lookups",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				provider := &trackingHeaderProvider{
					values: map[string][]string{
						"X-Forwarded-For": {"8.8.8.8"},
						"X-Real-IP":       {"7.7.7.7"},
					},
				}
				return Input{RemoteAddr: "5.5.5.5:80", Path: "/single-key", Headers: provider}, func() []string {
					return provider.calls
				}
			},
			wantRemoteAddr:    "5.5.5.5:80",
			wantPath:          "/single-key",
			wantHeaderValues:  []string{"8.8.8.8"},
			wantProviderCalls: []string{"X-Forwarded-For"},
		},
		{
			name:       "provider path does not prefetch unrelated headers",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				provider := &trackingHeaderProvider{
					values: map[string][]string{
						"X-Forwarded-For": {"8.8.8.8", "9.9.9.9"},
						"X-Real-IP":       {"7.7.7.7"},
					},
				}
				return Input{RemoteAddr: "6.6.6.6:80", Path: "/multiple-keys", Headers: provider}, func() []string {
					return provider.calls
				}
			},
			wantRemoteAddr:    "6.6.6.6:80",
			wantPath:          "/multiple-keys",
			wantHeaderValues:  []string{"8.8.8.8", "9.9.9.9"},
			wantProviderCalls: []string{"X-Forwarded-For"},
		},
		{
			name:       "HeaderValuesFunc provider path",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				calls := make([]string, 0, 1)
				headers := HeaderValuesFunc(func(name string) []string {
					calls = append(calls, name)
					if name == "X-Forwarded-For" {
						return []string{"8.8.8.8"}
					}
					return nil
				})
				return Input{RemoteAddr: "6.6.6.7:80", Path: "/header-func", Headers: headers}, func() []string {
					return calls
				}
			},
			wantRemoteAddr:    "6.6.6.7:80",
			wantPath:          "/header-func",
			wantHeaderValues:  []string{"8.8.8.8"},
			wantProviderCalls: []string{"X-Forwarded-For"},
		},
		{
			name:       "view only calls provider when Values is used",
			headerName: "X-Forwarded-For",
			newInput: func(t *testing.T) (Input, func() []string) {
				calls := make([]string, 0, 1)
				headers := HeaderValuesFunc(func(name string) []string {
					calls = append(calls, name)
					return nil
				})
				return Input{RemoteAddr: "7.7.7.7:80", Path: "/skip-provider", Headers: headers}, func() []string {
					return calls
				}
			},
			wantRemoteAddr:    "7.7.7.7:80",
			wantPath:          "/skip-provider",
			wantProviderCalls: []string{"X-Forwarded-For"},
		},
		{
			name:       "typed nil custom provider treated as absent",
			headerName: "X-Forwarded-For",
			newInput: func(*testing.T) (Input, func() []string) {
				return Input{
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
			view := requestViewFromInput(input)

			got := struct {
				RemoteAddr string
				Path       string
				Values     []string
			}{
				RemoteAddr: view.remoteAddr(),
				Path:       view.path(),
				Values:     view.values(tt.headerName),
			}

			want := struct {
				RemoteAddr string
				Path       string
				Values     []string
			}{
				RemoteAddr: tt.wantRemoteAddr,
				Path:       tt.wantPath,
				Values:     tt.wantHeaderValues,
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
		sourcePriority []Source
		want           []string
	}{
		{
			name:           "remote addr only",
			sourcePriority: []Source{SourceRemoteAddr},
		},
		{
			name:           "built-in chain header",
			sourcePriority: []Source{SourceXForwardedFor, SourceRemoteAddr},
			want:           []string{"X-Forwarded-For"},
		},
		{
			name:           "duplicate built-in alias",
			sourcePriority: []Source{SourceXForwardedFor, HeaderSource("X-Forwarded-For")},
			want:           []string{"X-Forwarded-For"},
		},
		{
			name:           "mixed built-in and custom headers",
			sourcePriority: []Source{SourceForwarded, SourceXRealIP, HeaderSource("cf-connecting-ip")},
			want:           []string{"Forwarded", "X-Real-IP", "Cf-Connecting-Ip"},
		},
		{
			name:           "duplicate custom header in different cases",
			sourcePriority: []Source{HeaderSource("CF-Connecting-IP"), HeaderSource("cf-connecting-ip"), HeaderSource("Cf-Connecting-Ip")},
			want:           []string{"Cf-Connecting-Ip"},
		},
		{
			name:           "distinct custom headers preserve different runtime keys",
			sourcePriority: []Source{HeaderSource("Foo-Bar"), HeaderSource("Foo_Bar")},
			want:           []string{"Foo-Bar", "Foo_bar"},
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

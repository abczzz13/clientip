package clientip

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
)

type countingResolverSource struct {
	calls      int
	result     Extraction
	err        error
	extractFn  func(requestView) (Extraction, error)
	sourceName Source
}

func (s *countingResolverSource) extract(req requestView) (Extraction, error) {
	s.calls++
	if s.extractFn != nil {
		return s.extractFn(req)
	}

	return s.result, s.err
}

func (s *countingResolverSource) name() string {
	return "counting"
}

func (s *countingResolverSource) sourceInfo() Source {
	if s.sourceName.valid() {
		return s.sourceName
	}
	if s.result.Source.valid() {
		return s.result.Source
	}

	return SourceRemoteAddr
}

func newResolverTestExtractor(source sourceExtractor) *Extractor {
	return &Extractor{
		config: &config{
			sourcePriority:   []Source{HeaderSource("X-Test-IP")},
			sourceHeaderKeys: []string{"X-Test-IP"},
		},
		source: source,
	}
}

func mustNewResolver(t *testing.T, extractor *Extractor, config ResolverConfig) *Resolver {
	t.Helper()

	resolver, err := NewResolver(extractor, config)
	if err != nil {
		t.Fatalf("NewResolver() error = %v", err)
	}

	return resolver
}

func TestNewResolver_InvalidConfig(t *testing.T) {
	extractor := newResolverTestExtractor(&countingResolverSource{})

	tests := []struct {
		name        string
		config      ResolverConfig
		wantErrText string
	}{
		{
			name:        "unsupported preferred fallback",
			config:      ResolverConfig{PreferredFallback: PreferredFallback(99)},
			wantErrText: "unsupported preferred fallback",
		},
		{
			name:        "static fallback requires static IP",
			config:      ResolverConfig{PreferredFallback: PreferredFallbackStaticIP},
			wantErrText: "PreferredFallbackStaticIP requires StaticFallbackIP",
		},
		{
			name: "remote addr fallback rejects static IP",
			config: ResolverConfig{
				PreferredFallback: PreferredFallbackRemoteAddr,
				StaticFallbackIP:  netip.MustParseAddr("0.0.0.0"),
			},
			wantErrText: "StaticFallbackIP requires PreferredFallbackStaticIP",
		},
		{
			name: "no fallback rejects static IP",
			config: ResolverConfig{
				StaticFallbackIP: netip.MustParseAddr("0.0.0.0"),
			},
			wantErrText: "StaticFallbackIP requires PreferredFallbackStaticIP",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := NewResolver(extractor, tt.config)
			if err == nil {
				t.Fatalf("NewResolver() error = nil, want containing %q", tt.wantErrText)
			}
			if !strings.Contains(err.Error(), tt.wantErrText) {
				t.Fatalf("NewResolver() error = %q, want containing %q", err.Error(), tt.wantErrText)
			}
		})
	}
}

func TestResolver_ResolveStrict_CachesSuccess(t *testing.T) {
	source := &countingResolverSource{
		result: Extraction{IP: netip.MustParseAddr("8.8.8.8"), Source: SourceXRealIP},
	}
	resolver := mustNewResolver(t, newResolverTestExtractor(source), ResolverConfig{})

	req := &http.Request{RemoteAddr: "203.0.113.10:443", Header: make(http.Header)}
	req, first := resolver.ResolveStrict(req)
	req, second := resolver.ResolveStrict(req)

	if source.calls != 1 {
		t.Fatalf("extract calls = %d, want 1", source.calls)
	}
	if first.Err != nil {
		t.Fatalf("first error = %v, want nil", first.Err)
	}
	if second.Err != nil {
		t.Fatalf("second error = %v, want nil", second.Err)
	}
	if got, want := second.IP, netip.MustParseAddr("8.8.8.8"); got != want {
		t.Fatalf("IP = %s, want %s", got, want)
	}
	if got, want := second.Source, SourceXRealIP; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}
	if second.FallbackUsed {
		t.Fatal("FallbackUsed = true, want false")
	}

	cached, ok := StrictResolutionFromContext(req.Context())
	if !ok {
		t.Fatal("StrictResolutionFromContext() found no cached resolution")
	}
	if cached != second {
		t.Fatalf("cached resolution = %#v, want %#v", cached, second)
	}
	if _, ok := PreferredResolutionFromContext(req.Context()); ok {
		t.Fatal("PreferredResolutionFromContext() = true, want false")
	}
}

func TestResolver_ResolveStrict_CachesFailure(t *testing.T) {
	strictErr := &ExtractionError{Err: ErrInvalidIP, Source: SourceXRealIP}
	source := &countingResolverSource{err: strictErr}
	resolver := mustNewResolver(t, newResolverTestExtractor(source), ResolverConfig{})

	req := &http.Request{RemoteAddr: "203.0.113.10:443", Header: make(http.Header)}
	req, first := resolver.ResolveStrict(req)
	req, second := resolver.ResolveStrict(req)

	if source.calls != 1 {
		t.Fatalf("extract calls = %d, want 1", source.calls)
	}
	if !errors.Is(first.Err, ErrInvalidIP) {
		t.Fatalf("first error = %v, want ErrInvalidIP", first.Err)
	}
	if !errors.Is(second.Err, ErrInvalidIP) {
		t.Fatalf("second error = %v, want ErrInvalidIP", second.Err)
	}
	if second.OK() {
		t.Fatal("OK() = true, want false")
	}
	if got, want := second.Source, SourceXRealIP; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}

	cached, ok := StrictResolutionFromContext(req.Context())
	if !ok {
		t.Fatal("StrictResolutionFromContext() found no cached resolution")
	}
	if !errors.Is(cached.Err, ErrInvalidIP) {
		t.Fatalf("cached error = %v, want ErrInvalidIP", cached.Err)
	}
}

func TestResolver_ResolvePreferred_ReusesStrictCachedResult(t *testing.T) {
	source := &countingResolverSource{
		result: Extraction{IP: netip.MustParseAddr("8.8.8.8"), Source: SourceXRealIP},
	}
	resolver := mustNewResolver(t, newResolverTestExtractor(source), ResolverConfig{PreferredFallback: PreferredFallbackRemoteAddr})

	req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}
	req, strict := resolver.ResolveStrict(req)
	req, preferred := resolver.ResolvePreferred(req)

	if source.calls != 1 {
		t.Fatalf("extract calls = %d, want 1", source.calls)
	}
	if strict != preferred {
		t.Fatalf("preferred resolution = %#v, want %#v", preferred, strict)
	}
	if preferred.FallbackUsed {
		t.Fatal("FallbackUsed = true, want false")
	}

	cached, ok := PreferredResolutionFromContext(req.Context())
	if !ok {
		t.Fatal("PreferredResolutionFromContext() found no cached resolution")
	}
	if cached != preferred {
		t.Fatalf("cached preferred resolution = %#v, want %#v", cached, preferred)
	}
}

func TestResolver_ResolvePreferred_ParseRemoteAddrFallback(t *testing.T) {
	strictErr := &ExtractionError{Err: ErrInvalidIP, Source: SourceXRealIP}
	source := &countingResolverSource{err: strictErr}
	resolver := mustNewResolver(t, newResolverTestExtractor(source), ResolverConfig{PreferredFallback: PreferredFallbackRemoteAddr})

	req := &http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}
	req, resolution := resolver.ResolvePreferred(req)

	if source.calls != 1 {
		t.Fatalf("extract calls = %d, want 1", source.calls)
	}
	if !resolution.OK() {
		t.Fatalf("ResolvePreferred() error = %v", resolution.Err)
	}
	if !resolution.FallbackUsed {
		t.Fatal("FallbackUsed = false, want true")
	}
	if got, want := resolution.IP, netip.MustParseAddr("127.0.0.1"); got != want {
		t.Fatalf("IP = %s, want %s", got, want)
	}
	if got, want := resolution.Source, SourceRemoteAddr; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}

	strict, ok := StrictResolutionFromContext(req.Context())
	if !ok {
		t.Fatal("StrictResolutionFromContext() found no cached strict resolution")
	}
	if !errors.Is(strict.Err, ErrInvalidIP) {
		t.Fatalf("strict error = %v, want ErrInvalidIP", strict.Err)
	}

	preferred, ok := PreferredResolutionFromContext(req.Context())
	if !ok {
		t.Fatal("PreferredResolutionFromContext() found no cached preferred resolution")
	}
	if preferred != resolution {
		t.Fatalf("cached preferred resolution = %#v, want %#v", preferred, resolution)
	}
}

func TestResolver_ResolvePreferred_StaticFallback(t *testing.T) {
	strictErr := &ExtractionError{Err: ErrInvalidIP, Source: SourceXRealIP}
	source := &countingResolverSource{err: strictErr}
	resolver := mustNewResolver(t, newResolverTestExtractor(source), ResolverConfig{
		PreferredFallback: PreferredFallbackStaticIP,
		StaticFallbackIP:  netip.MustParseAddr("0.0.0.0"),
	})

	req := &http.Request{RemoteAddr: "bad-remote-addr", Header: make(http.Header)}
	req, resolution := resolver.ResolvePreferred(req)

	if source.calls != 1 {
		t.Fatalf("extract calls = %d, want 1", source.calls)
	}
	if !resolution.OK() {
		t.Fatalf("ResolvePreferred() error = %v", resolution.Err)
	}
	if !resolution.FallbackUsed {
		t.Fatal("FallbackUsed = false, want true")
	}
	if got, want := resolution.IP, netip.MustParseAddr("0.0.0.0"); got != want {
		t.Fatalf("IP = %s, want %s", got, want)
	}
	if got, want := resolution.Source, SourceStaticFallback; got != want {
		t.Fatalf("Source = %q, want %q", got, want)
	}

	strict, ok := StrictResolutionFromContext(req.Context())
	if !ok {
		t.Fatal("StrictResolutionFromContext() found no cached strict resolution")
	}
	if !errors.Is(strict.Err, ErrInvalidIP) {
		t.Fatalf("strict error = %v, want ErrInvalidIP", strict.Err)
	}
}

func TestResolver_ResolvePreferred_DoesNotFallbackOnCanceledOrDeadline(t *testing.T) {
	resolver := mustNewResolver(t, newResolverTestExtractor(&countingResolverSource{
		extractFn: func(req requestView) (Extraction, error) {
			return Extraction{}, req.context().Err()
		},
	}), ResolverConfig{PreferredFallback: PreferredFallbackRemoteAddr})

	tests := []struct {
		name       string
		newRequest func() *http.Request
		newInput   func() Input
		wantErr    error
	}{
		{
			name: "request canceled",
			newRequest: func() *http.Request {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				return (&http.Request{RemoteAddr: "127.0.0.1:8080", Header: make(http.Header)}).WithContext(ctx)
			},
			wantErr: context.Canceled,
		},
		{
			name: "input deadline exceeded",
			newInput: func() Input {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				return Input{Context: ctx, RemoteAddr: "127.0.0.1:8080"}
			},
			wantErr: context.DeadlineExceeded,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.newRequest != nil {
				req, resolution := resolver.ResolvePreferred(tt.newRequest())
				if !errors.Is(resolution.Err, tt.wantErr) {
					t.Fatalf("error = %v, want %v", resolution.Err, tt.wantErr)
				}
				if resolution.FallbackUsed {
					t.Fatal("FallbackUsed = true, want false")
				}
				if preferred, ok := PreferredResolutionFromContext(req.Context()); !ok || !errors.Is(preferred.Err, tt.wantErr) {
					t.Fatalf("cached preferred = %#v, ok=%t, want error %v", preferred, ok, tt.wantErr)
				}
				return
			}

			input, resolution := resolver.ResolveInputPreferred(tt.newInput())
			if !errors.Is(resolution.Err, tt.wantErr) {
				t.Fatalf("error = %v, want %v", resolution.Err, tt.wantErr)
			}
			if resolution.FallbackUsed {
				t.Fatal("FallbackUsed = true, want false")
			}
			if preferred, ok := PreferredResolutionFromContext(input.Context); !ok || !errors.Is(preferred.Err, tt.wantErr) {
				t.Fatalf("cached preferred = %#v, ok=%t, want error %v", preferred, ok, tt.wantErr)
			}
		})
	}
}

func TestResolver_ResolveInputStrict_CachesSuccess(t *testing.T) {
	source := &countingResolverSource{
		result: Extraction{IP: netip.MustParseAddr("2001:db8::1"), Source: SourceXRealIP},
	}
	resolver := mustNewResolver(t, newResolverTestExtractor(source), ResolverConfig{})

	input := Input{Context: context.Background(), RemoteAddr: "203.0.113.10:443"}
	input, first := resolver.ResolveInputStrict(input)
	input, second := resolver.ResolveInputStrict(input)

	if source.calls != 1 {
		t.Fatalf("extract calls = %d, want 1", source.calls)
	}
	if first != second {
		t.Fatalf("second resolution = %#v, want %#v", second, first)
	}
	if cached, ok := StrictResolutionFromContext(input.Context); !ok || cached != second {
		t.Fatalf("cached strict = %#v, ok=%t, want %#v", cached, ok, second)
	}
}

type resolutionView struct {
	IP           string
	Source       Source
	ErrInvalidIP bool
	FallbackUsed bool
}

func viewResolution(r Resolution) resolutionView {
	view := resolutionView{Source: r.Source, FallbackUsed: r.FallbackUsed}
	if r.IP.IsValid() {
		view.IP = r.IP.String()
	}
	view.ErrInvalidIP = errors.Is(r.Err, ErrInvalidIP)
	return view
}

func TestResolverState_ResolveStrict_CachesComputedValue(t *testing.T) {
	var state resolverState
	computeCalls := 0
	first := state.ResolveStrict(func() Resolution {
		computeCalls++
		return Resolution{Extraction: Extraction{Source: SourceXRealIP}}
	})
	second := state.ResolveStrict(func() Resolution {
		computeCalls++
		return Resolution{Extraction: Extraction{Source: SourceRemoteAddr}}
	})

	if got, want := first.Source, SourceXRealIP; got != want {
		t.Fatalf("first strict source = %q, want %q", got, want)
	}
	if got, want := second.Source, SourceXRealIP; got != want {
		t.Fatalf("second strict source = %q, want %q", got, want)
	}
	if got, want := computeCalls, 1; got != want {
		t.Fatalf("strict compute calls = %d, want %d", got, want)
	}

	if got, ok := state.StrictValue(); !ok || got.Source != SourceXRealIP {
		t.Fatalf("StrictValue() = (%#v, %t), want source %q", got, ok, SourceXRealIP)
	}
	if _, ok := state.PreferredValue(); ok {
		t.Fatal("PreferredValue() ok = true, want false")
	}
}

func TestResolverState_ResolvePreferred(t *testing.T) {
	tests := []struct {
		name              string
		strict            Resolution
		shouldFallback    func(Resolution) bool
		fallback          func(Resolution) (Resolution, bool)
		wantPreferred     Resolution
		wantStrict        Resolution
		wantStrictCalls   int
		wantFallbackCalls int
	}{
		{
			name:           "reuses strict result when fallback does not apply",
			strict:         Resolution{Extraction: Extraction{Source: SourceXRealIP}},
			shouldFallback: func(r Resolution) bool { return r.Err != nil },
			fallback: func(Resolution) (Resolution, bool) {
				return Resolution{Extraction: Extraction{Source: SourceRemoteAddr}, FallbackUsed: true}, true
			},
			wantPreferred:     Resolution{Extraction: Extraction{Source: SourceXRealIP}},
			wantStrict:        Resolution{Extraction: Extraction{Source: SourceXRealIP}},
			wantStrictCalls:   1,
			wantFallbackCalls: 0,
		},
		{
			name:           "uses fallback when allowed",
			strict:         Resolution{Err: ErrInvalidIP},
			shouldFallback: func(r Resolution) bool { return r.Err != nil },
			fallback: func(Resolution) (Resolution, bool) {
				return Resolution{Extraction: Extraction{Source: SourceRemoteAddr}, FallbackUsed: true}, true
			},
			wantPreferred:     Resolution{Extraction: Extraction{Source: SourceRemoteAddr}, FallbackUsed: true},
			wantStrict:        Resolution{Err: ErrInvalidIP},
			wantStrictCalls:   1,
			wantFallbackCalls: 1,
		},
		{
			name:           "keeps strict value when fallback declines",
			strict:         Resolution{Err: ErrInvalidIP},
			shouldFallback: func(r Resolution) bool { return r.Err != nil },
			fallback: func(Resolution) (Resolution, bool) {
				return Resolution{Extraction: Extraction{Source: SourceRemoteAddr}, FallbackUsed: true}, false
			},
			wantPreferred:     Resolution{Err: ErrInvalidIP},
			wantStrict:        Resolution{Err: ErrInvalidIP},
			wantStrictCalls:   1,
			wantFallbackCalls: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var state resolverState
			strictCalls := 0
			fallbackCalls := 0

			first := state.ResolvePreferred(
				func() Resolution {
					strictCalls++
					return tt.strict
				},
				tt.shouldFallback,
				func(r Resolution) (Resolution, bool) {
					fallbackCalls++
					return tt.fallback(r)
				},
			)
			second := state.ResolvePreferred(
				func() Resolution {
					strictCalls++
					return Resolution{Extraction: Extraction{Source: SourceStaticFallback}}
				},
				tt.shouldFallback,
				func(r Resolution) (Resolution, bool) {
					fallbackCalls++
					return tt.fallback(r)
				},
			)

			if diff := cmp.Diff(viewResolution(tt.wantPreferred), viewResolution(first)); diff != "" {
				t.Fatalf("first preferred mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(viewResolution(tt.wantPreferred), viewResolution(second)); diff != "" {
				t.Fatalf("second preferred mismatch (-want +got):\n%s", diff)
			}
			if got, want := strictCalls, tt.wantStrictCalls; got != want {
				t.Fatalf("strict compute calls = %d, want %d", got, want)
			}
			if got, want := fallbackCalls, tt.wantFallbackCalls; got != want {
				t.Fatalf("fallback calls = %d, want %d", got, want)
			}

			if diff := cmp.Diff(viewResolution(tt.wantStrict), viewResolution(mustStrictValue(t, &state))); diff != "" {
				t.Fatalf("strict cache mismatch (-want +got):\n%s", diff)
			}
			if diff := cmp.Diff(viewResolution(tt.wantPreferred), viewResolution(mustPreferredValue(t, &state))); diff != "" {
				t.Fatalf("preferred cache mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestResolverState_ResolveStrict_ConcurrentAccessComputesOnce(t *testing.T) {
	var state resolverState
	var computeCalls atomic.Int32

	const goroutines = 16
	start := make(chan struct{})
	values := make(chan Source, goroutines)

	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			values <- state.ResolveStrict(func() Resolution {
				computeCalls.Add(1)
				time.Sleep(5 * time.Millisecond)
				return Resolution{Extraction: Extraction{Source: SourceXRealIP}}
			}).Source
		}()
	}

	close(start)
	wg.Wait()
	close(values)

	got := make([]Source, 0, goroutines)
	for value := range values {
		got = append(got, value)
	}

	want := make([]Source, goroutines)
	for i := range want {
		want[i] = SourceXRealIP
	}

	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("concurrent strict values mismatch (-want +got):\n%s", diff)
	}
	if got, want := int(computeCalls.Load()), 1; got != want {
		t.Fatalf("strict compute calls = %d, want %d", got, want)
	}
}

func mustStrictValue(t *testing.T, state *resolverState) Resolution {
	t.Helper()
	value, ok := state.StrictValue()
	if !ok {
		t.Fatal("StrictValue() ok = false, want true")
	}
	return value
}

func mustPreferredValue(t *testing.T, state *resolverState) Resolution {
	t.Helper()
	value, ok := state.PreferredValue()
	if !ok {
		t.Fatal("PreferredValue() ok = false, want true")
	}
	return value
}

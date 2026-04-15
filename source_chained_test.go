package clientip

import (
	"context"
	"errors"
	"net/netip"
	"testing"
)

// mockSourceExtractor is a test double for sourceExtractor.
type mockSourceExtractor struct {
	extractFn   func(r requestView) (Extraction, error)
	nameValue   string
	sourceValue Source
}

func (m *mockSourceExtractor) extract(r requestView) (Extraction, error) {
	return m.extractFn(r)
}

func (m *mockSourceExtractor) name() string {
	return m.nameValue
}

func (m *mockSourceExtractor) sourceInfo() Source {
	return m.sourceValue
}

func TestChainedSource_ReturnsFirstSuccess(t *testing.T) {
	wantIP := netip.MustParseAddr("1.2.3.4")
	wantSource := SourceXForwardedFor

	first := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{IP: wantIP, Source: wantSource}, nil
		},
		nameValue: "first",
	}
	second := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			t.Fatal("second source should not be called")
			return Extraction{}, nil
		},
		nameValue: "second",
	}

	chain := newChainedSource(nil, first, second)
	result, err := chain.extract(requestView{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
	if result.Source != wantSource {
		t.Errorf("Source = %v, want %v", result.Source, wantSource)
	}
}

func TestChainedSource_SkipsNonTerminalErrors(t *testing.T) {
	wantIP := netip.MustParseAddr("5.6.7.8")
	nonTerminal := errors.New("not terminal")

	first := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{}, nonTerminal
		},
		nameValue: "first",
	}
	second := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{IP: wantIP, Source: SourceRemoteAddr}, nil
		},
		nameValue: "second",
	}

	chain := newChainedSource(sourceIsTerminalError, first, second)
	result, err := chain.extract(requestView{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestChainedSource_SkipsErrSourceUnavailable(t *testing.T) {
	wantIP := netip.MustParseAddr("10.0.0.1")

	unavailable := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{}, &ExtractionError{Err: ErrSourceUnavailable, Source: SourceXForwardedFor}
		},
		nameValue: "unavailable",
	}
	fallback := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{IP: wantIP, Source: SourceRemoteAddr}, nil
		},
		nameValue: "fallback",
	}

	chain := newChainedSource(sourceIsTerminalError, unavailable, fallback)
	result, err := chain.extract(requestView{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result.IP != wantIP {
		t.Errorf("IP = %v, want %v", result.IP, wantIP)
	}
}

func TestChainedSource_ContextCanceledIsTerminal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	first := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{}, context.Canceled
		},
		nameValue: "first",
	}
	second := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			t.Fatal("second source should not be called after terminal error")
			return Extraction{}, nil
		},
		nameValue: "second",
	}

	chain := newChainedSource(sourceIsTerminalError, first, second)
	_, err := chain.extract(requestView{ctx: ctx})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
}

func TestChainedSource_TerminalErrorStopsChain(t *testing.T) {
	terminalErr := &ExtractionError{Err: ErrUntrustedProxy, Source: SourceXForwardedFor}

	first := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{}, terminalErr
		},
		nameValue: "first",
	}
	second := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			t.Fatal("second source should not be called after terminal error")
			return Extraction{}, nil
		},
		nameValue: "second",
	}

	chain := newChainedSource(sourceIsTerminalError, first, second)
	_, err := chain.extract(requestView{})
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if !errors.Is(err, ErrUntrustedProxy) {
		t.Errorf("error = %v, want ErrUntrustedProxy", err)
	}
}

func TestChainedSource_AllFailReturnsLastError(t *testing.T) {
	err1 := &ExtractionError{Err: ErrSourceUnavailable, Source: SourceXForwardedFor}
	err2 := &ExtractionError{Err: ErrSourceUnavailable, Source: SourceRemoteAddr}

	first := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{}, err1
		},
		nameValue: "first",
	}
	second := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			return Extraction{}, err2
		},
		nameValue: "second",
	}

	chain := newChainedSource(sourceIsTerminalError, first, second)
	_, err := chain.extract(requestView{})
	if !errors.Is(err, err2) {
		t.Errorf("error = %v, want %v (last error)", err, err2)
	}
}

func TestChainedSource_Name(t *testing.T) {
	a := &mockSourceExtractor{nameValue: "alpha"}
	b := &mockSourceExtractor{nameValue: "beta"}
	chain := newChainedSource(nil, a, b)

	want := "chained[alpha,beta]"
	if got := chain.name(); got != want {
		t.Errorf("name() = %q, want %q", got, want)
	}
}

func TestChainedSource_SourceInfo(t *testing.T) {
	chain := newChainedSource(nil, &mockSourceExtractor{nameValue: "a"})
	got := chain.sourceInfo()
	if got.valid() {
		t.Errorf("sourceInfo() should return invalid Source, got %v", got)
	}
}

func TestChainedSource_ContextCanceledBeforeSecondSource(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())

	firstCalled := false
	secondCalled := false
	first := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			firstCalled = true
			cancel() // cancel context after first source runs
			return Extraction{}, &ExtractionError{Err: ErrSourceUnavailable, Source: SourceXForwardedFor}
		},
		nameValue: "first",
	}
	second := &mockSourceExtractor{
		extractFn: func(r requestView) (Extraction, error) {
			secondCalled = true
			return Extraction{}, nil
		},
		nameValue: "second",
	}

	chain := newChainedSource(sourceIsTerminalError, first, second)
	_, err := chain.extract(requestView{ctx: ctx})
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
	if !errors.Is(err, context.Canceled) {
		t.Errorf("error = %v, want context.Canceled", err)
	}
	if !firstCalled {
		t.Error("first source should have been called")
	}
	if secondCalled {
		t.Error("second source should not be called after context cancellation")
	}
}

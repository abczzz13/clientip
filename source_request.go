package clientip

import (
	"context"
	"net/http"
	"net/textproto"
)

type headerValuesFunc func(name string) []string

type requestView struct {
	ctx             context.Context
	remoteAddrValue string
	pathValue       string
	headerMap       map[string][]string
	headerFunc      headerValuesFunc
}

func (r requestView) context() context.Context {
	if r.ctx == nil {
		return context.Background()
	}

	return r.ctx
}

func (r requestView) remoteAddr() string {
	return r.remoteAddrValue
}

func (r requestView) path() string {
	return r.pathValue
}

func (r requestView) values(name string) []string {
	if r.headerMap != nil {
		return r.headerMap[textproto.CanonicalMIMEHeaderKey(name)]
	}
	if r.headerFunc != nil {
		return r.headerFunc(name)
	}

	return nil
}

// valuesCanonical performs a header lookup without canonicalizing the name.
// Callers must pass an already-canonical MIME header key (e.g. "X-Forwarded-For").
func (r requestView) valuesCanonical(name string) []string {
	if r.headerMap != nil {
		return r.headerMap[name]
	}
	if r.headerFunc != nil {
		return r.headerFunc(name)
	}

	return nil
}

func requestViewFromRequest(r *http.Request) requestView {
	if r == nil {
		return requestView{}
	}

	view := requestView{
		ctx:             r.Context(),
		remoteAddrValue: r.RemoteAddr,
		headerMap:       map[string][]string(r.Header),
	}
	if r.URL != nil {
		view.pathValue = r.URL.Path
	}

	return view
}

func requestViewFromInput(input Input) requestView {
	view := requestView{
		ctx:             requestInputContext(input),
		remoteAddrValue: input.RemoteAddr,
		pathValue:       input.Path,
	}
	if input.Headers == nil {
		return view
	}

	if h, ok := input.Headers.(HeaderValuesFunc); ok {
		if h == nil {
			return view
		}
		view.headerFunc = headerValuesFunc(h)
		return view
	}

	// Deliberately catch typed nils (e.g. (*myHeaders)(nil)) so they behave
	// the same as an unset Headers field rather than panicking at call time.
	if isNilValue(input.Headers) {
		return view
	}

	view.headerFunc = func(name string) []string {
		return input.Headers.Values(name)
	}
	return view
}

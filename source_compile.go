package clientip

type sourceExtractor interface {
	extract(r requestView) (Extraction, error)
	name() string
	sourceInfo() Source
}

type sourceExtractorKind uint8

const (
	sourceExtractorKindForwarded sourceExtractorKind = iota + 1
	sourceExtractorKindXForwardedFor
	sourceExtractorKindSingleHeader
	sourceExtractorKindRemoteAddr
)

type sourceSpec struct {
	kind       sourceExtractorKind
	source     Source
	headerName string
}

type sourceExecuteFunc func(requestView, sourceSpec) (Extraction, error)

type compiledSource struct {
	spec    sourceSpec
	execute sourceExecuteFunc
}

func compileSource(spec sourceSpec, execute sourceExecuteFunc) sourceExtractor {
	return &compiledSource{spec: spec, execute: execute}
}

func (s *compiledSource) extract(r requestView) (Extraction, error) {
	return s.execute(r, s.spec)
}

func (s *compiledSource) name() string {
	return s.spec.source.String()
}

func (s *compiledSource) sourceInfo() Source {
	return s.spec.source
}

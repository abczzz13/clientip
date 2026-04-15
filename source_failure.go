package clientip

type extractionFailureKind uint8

const (
	failureUnknown extractionFailureKind = iota
	failureSourceUnavailable
	failureMultipleHeaders
	failureUntrustedProxy
	failureProxyValidation
	failureEmptyChain
	failureInvalidClientIP
)

// errSourceUnavailable is a pre-allocated sentinel returned by extractors
// when the source header is absent. Only the kind field is read by callers.
var errSourceUnavailable = &extractionFailure{kind: failureSourceUnavailable}

type extractionFailure struct {
	kind                extractionFailureKind
	source              Source
	headerName          string
	headerCount         int
	remoteAddr          string
	chain               string
	index               int
	extractedIP         string
	trustedProxyCount   int
	minTrustedProxies   int
	maxTrustedProxies   int
	clientIPDisposition clientIPDisposition
}

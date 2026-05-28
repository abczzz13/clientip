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

// errSourceUnavailable is a pre-allocated sentinel returned by extractors when
// the source header is absent. Only the kind field is read by callers.
var errSourceUnavailable = &extractionFailure{kind: failureSourceUnavailable}

// extractionFailure is the internal policy-failure shape returned by low-level
// source extractors. source_execution.go is responsible for turning these into
// public sentinel/typed errors and security log events.
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

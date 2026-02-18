package clientip

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	// ErrNoTrustedProxies indicates no trusted proxies were found in a parsed
	// chain when at least one is required.
	ErrNoTrustedProxies = errors.New("no trusted proxies found in proxy chain")

	// ErrSourceUnavailable indicates the selected source is not present on the
	// request.
	ErrSourceUnavailable = errors.New("source unavailable")

	// ErrMultipleSingleIPHeaders indicates multiple values were provided for a
	// single-IP header source.
	ErrMultipleSingleIPHeaders = errors.New("multiple single-IP headers received")

	// ErrUntrustedProxy indicates a header source was provided by an untrusted
	// immediate proxy.
	ErrUntrustedProxy = errors.New("request from untrusted proxy")

	// ErrTooFewTrustedProxies indicates trusted proxies in the chain are below
	// the configured minimum.
	ErrTooFewTrustedProxies = errors.New("too few trusted proxies in proxy chain")

	// ErrTooManyTrustedProxies indicates trusted proxies in the chain exceed the
	// configured maximum.
	ErrTooManyTrustedProxies = errors.New("too many trusted proxies in proxy chain")

	// ErrInvalidIP indicates the extracted client IP is invalid or implausible.
	ErrInvalidIP = errors.New("invalid or implausible IP address")

	// ErrChainTooLong indicates a Forwarded/X-Forwarded-For chain exceeded the
	// configured maximum length.
	ErrChainTooLong = errors.New("proxy chain too long")

	// ErrInvalidForwardedHeader indicates a malformed RFC7239 Forwarded header.
	ErrInvalidForwardedHeader = errors.New("invalid Forwarded header")
)

// ExtractionError wraps a source-specific extraction failure.
type ExtractionError struct {
	Err    error
	Source string
}

// Error implements error.
func (e *ExtractionError) Error() string {
	return fmt.Sprintf("%s: %v", e.Source, e.Err)
}

// Unwrap returns the underlying sentinel or wrapped error.
func (e *ExtractionError) Unwrap() error {
	return e.Err
}

// SourceName returns the source identifier associated with this error.
func (e *ExtractionError) SourceName() string {
	return e.Source
}

// MultipleHeadersError reports duplicate header-line values for a source that
// expects a single header line.
type MultipleHeadersError struct {
	ExtractionError
	HeaderCount int
	HeaderName  string
	RemoteAddr  string
}

// Error implements error.
func (e *MultipleHeadersError) Error() string {
	if e.HeaderName != "" {
		return fmt.Sprintf("%s: %v (header=%q, header_count=%d, remote_addr=%s)",
			e.Source, e.Err, e.HeaderName, e.HeaderCount, e.RemoteAddr)
	}

	return fmt.Sprintf("%s: %v (header_count=%d, remote_addr=%s)",
		e.Source, e.Err, e.HeaderCount, e.RemoteAddr)
}

// ProxyValidationError reports failures from trusted-proxy chain validation.
type ProxyValidationError struct {
	ExtractionError
	Chain             string
	TrustedProxyCount int
	MinTrustedProxies int
	MaxTrustedProxies int
}

// Error implements error.
func (e *ProxyValidationError) Error() string {
	return fmt.Sprintf("%s: %v (chain=%q, trusted_count=%d, min=%d, max=%d)",
		e.Source, e.Err, e.Chain, e.TrustedProxyCount, e.MinTrustedProxies, e.MaxTrustedProxies)
}

// InvalidIPError reports an invalid or implausible extracted client IP.
type InvalidIPError struct {
	ExtractionError
	Chain          string
	ExtractedIP    string
	Index          int
	TrustedProxies int
}

// Error implements error.
func (e *InvalidIPError) Error() string {
	if e.Chain != "" {
		return fmt.Sprintf("%s: %v (chain=%q, extracted_ip=%q, index=%d, trusted_proxies=%d)",
			e.Source, e.Err, e.Chain, e.ExtractedIP, e.Index, e.TrustedProxies)
	}
	if e.ExtractedIP != "" {
		return fmt.Sprintf("%s: %v (ip=%q)", e.Source, e.Err, e.ExtractedIP)
	}
	return e.ExtractionError.Error()
}

// RemoteAddrError reports an invalid or implausible Request.RemoteAddr value.
type RemoteAddrError struct {
	ExtractionError
	RemoteAddr string
}

// Error implements error.
func (e *RemoteAddrError) Error() string {
	return fmt.Sprintf("%s: %v (remote_addr=%q)", e.Source, e.Err, e.RemoteAddr)
}

// ChainTooLongError reports an overlong Forwarded/X-Forwarded-For chain.
type ChainTooLongError struct {
	ExtractionError
	ChainLength int
	MaxLength   int
}

// Error implements error.
func (e *ChainTooLongError) Error() string {
	return fmt.Sprintf("%s: %v (chain_length=%d, max_length=%d)",
		e.Source, e.Err, e.ChainLength, e.MaxLength)
}

// ChainDebugInfo describes parsed chain-analysis details for diagnostics.
type ChainDebugInfo struct {
	FullChain      []string
	ClientIndex    int
	TrustedIndices []int
}

// Extraction contains extraction metadata.
//
// On error, Source may still be set when available.
//
// For additional diagnostics (such as chain details or trusted-proxy counts),
// inspect typed errors like ProxyValidationError and InvalidIPError.
type Extraction struct {
	IP netip.Addr

	Source string

	TrustedProxyCount int

	DebugInfo *ChainDebugInfo
}

// ParseCIDRs parses one or more CIDR strings.
func ParseCIDRs(cidrs ...string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(cidrs))
	for _, cidr := range cidrs {
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		prefixes = append(prefixes, prefix)
	}
	return prefixes, nil
}

// NormalizeSourceName canonicalizes a source/header name for reporting.
//
// It lowercases the value and replaces hyphens with underscores.
func NormalizeSourceName(headerName string) string {
	return strings.ToLower(strings.ReplaceAll(headerName, "-", "_"))
}

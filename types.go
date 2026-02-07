package clientip

import (
	"errors"
	"fmt"
	"net/netip"
	"strings"
)

var (
	ErrNoTrustedProxies = errors.New("no trusted proxies found in X-Forwarded-For chain")

	ErrMultipleXFFHeaders = errors.New("multiple X-Forwarded-For headers received")

	ErrUntrustedProxy = errors.New("request from untrusted proxy")

	ErrTooFewTrustedProxies = errors.New("too few trusted proxies in X-Forwarded-For chain")

	ErrTooManyTrustedProxies = errors.New("too many trusted proxies in X-Forwarded-For chain")

	ErrInvalidIP = errors.New("invalid or implausible IP address")

	ErrChainTooLong = errors.New("X-Forwarded-For chain too long")
)

type ExtractionError struct {
	Err    error
	Source string
}

func (e *ExtractionError) Error() string {
	return fmt.Sprintf("%s: %v", e.Source, e.Err)
}

func (e *ExtractionError) Unwrap() error {
	return e.Err
}

func (e *ExtractionError) SourceName() string {
	return e.Source
}

type MultipleHeadersError struct {
	ExtractionError
	HeaderCount int
	RemoteAddr  string
}

func (e *MultipleHeadersError) Error() string {
	return fmt.Sprintf("%s: %v (header_count=%d, remote_addr=%s)",
		e.Source, e.Err, e.HeaderCount, e.RemoteAddr)
}

type ProxyValidationError struct {
	ExtractionError
	XFF               string
	TrustedProxyCount int
	MinTrustedProxies int
	MaxTrustedProxies int
}

func (e *ProxyValidationError) Error() string {
	return fmt.Sprintf("%s: %v (xff=%q, trusted_count=%d, min=%d, max=%d)",
		e.Source, e.Err, e.XFF, e.TrustedProxyCount, e.MinTrustedProxies, e.MaxTrustedProxies)
}

type InvalidIPError struct {
	ExtractionError
	XFF            string
	ExtractedIP    string
	Index          int
	TrustedProxies int
}

func (e *InvalidIPError) Error() string {
	if e.XFF != "" {
		return fmt.Sprintf("%s: %v (xff=%q, extracted_ip=%q, index=%d, trusted_proxies=%d)",
			e.Source, e.Err, e.XFF, e.ExtractedIP, e.Index, e.TrustedProxies)
	}
	if e.ExtractedIP != "" {
		return fmt.Sprintf("%s: %v (ip=%q)", e.Source, e.Err, e.ExtractedIP)
	}
	return e.ExtractionError.Error()
}

type RemoteAddrError struct {
	ExtractionError
	RemoteAddr string
}

func (e *RemoteAddrError) Error() string {
	return fmt.Sprintf("%s: %v (remote_addr=%q)", e.Source, e.Err, e.RemoteAddr)
}

type ChainTooLongError struct {
	ExtractionError
	ChainLength int
	MaxLength   int
}

func (e *ChainTooLongError) Error() string {
	return fmt.Sprintf("%s: %v (chain_length=%d, max_length=%d)",
		e.Source, e.Err, e.ChainLength, e.MaxLength)
}

type ChainDebugInfo struct {
	FullChain      []string
	ClientIndex    int
	TrustedIndices []int
}

type Result struct {
	IP netip.Addr

	Source string

	Err error

	TrustedProxyCount int

	DebugInfo *ChainDebugInfo
}

func (r Result) Valid() bool {
	return r.Err == nil && r.IP.IsValid()
}

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

func NormalizeSourceName(headerName string) string {
	return strings.ToLower(strings.ReplaceAll(headerName, "-", "_"))
}

package clientip

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseCIDRs(t *testing.T) {
	tests := []struct {
		name    string
		cidrs   []string
		want    []netip.Prefix
		wantErr bool
	}{
		{
			name:  "valid single CIDR",
			cidrs: []string{"10.0.0.0/8"},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
			},
			wantErr: false,
		},
		{
			name:  "valid multiple CIDRs",
			cidrs: []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"},
			want: []netip.Prefix{
				netip.MustParsePrefix("10.0.0.0/8"),
				netip.MustParsePrefix("172.16.0.0/12"),
				netip.MustParsePrefix("192.168.0.0/16"),
			},
			wantErr: false,
		},
		{
			name:  "valid IPv6 CIDR",
			cidrs: []string{"2001:db8::/32"},
			want: []netip.Prefix{
				netip.MustParsePrefix("2001:db8::/32"),
			},
			wantErr: false,
		},
		{
			name:    "invalid CIDR",
			cidrs:   []string{"10.0.0.0"},
			wantErr: true,
		},
		{
			name:    "invalid CIDR in list",
			cidrs:   []string{"10.0.0.0/8", "invalid", "192.168.0.0/16"},
			wantErr: true,
		},
		{
			name:    "empty string",
			cidrs:   []string{""},
			wantErr: true,
		},
		{
			name:    "empty list",
			cidrs:   []string{},
			want:    []netip.Prefix{},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCIDRs(tt.cidrs...)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCIDRs() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !tt.wantErr {
				if len(got) != len(tt.want) {
					t.Errorf("ParseCIDRs() got %d prefixes, want %d", len(got), len(tt.want))
					return
				}
				for i := range got {
					if got[i] != tt.want[i] {
						t.Errorf("ParseCIDRs()[%d] = %v, want %v", i, got[i], tt.want[i])
					}
				}
			}
		})
	}
}

func TestTypedErrors_ErrorFormatting(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "ExtractionError",
			err:  &ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
			want: "remote_addr: invalid or implausible IP address",
		},
		{
			name: "MultipleHeadersError with header name",
			err: &MultipleHeadersError{
				ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: SourceXRealIP},
				HeaderCount:     2,
				HeaderName:      "X-Real-IP",
				RemoteAddr:      "1.1.1.1:12345",
			},
			want: `x_real_ip: multiple single-IP headers received (header="X-Real-IP", header_count=2, remote_addr=1.1.1.1:12345)`,
		},
		{
			name: "MultipleHeadersError without header name",
			err: &MultipleHeadersError{
				ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: SourceXRealIP},
				HeaderCount:     3,
				RemoteAddr:      "2.2.2.2:4321",
			},
			want: `x_real_ip: multiple single-IP headers received (header_count=3, remote_addr=2.2.2.2:4321)`,
		},
		{
			name: "ProxyValidationError",
			err: &ProxyValidationError{
				ExtractionError:   ExtractionError{Err: ErrTooFewTrustedProxies, Source: SourceXForwardedFor},
				Chain:             "1.1.1.1, 10.0.0.1",
				TrustedProxyCount: 1,
				MinTrustedProxies: 2,
				MaxTrustedProxies: 3,
			},
			want: `x_forwarded_for: too few trusted proxies in proxy chain (chain="1.1.1.1, 10.0.0.1", trusted_count=1, min=2, max=3)`,
		},
		{
			name: "InvalidIPError with chain",
			err: &InvalidIPError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceXForwardedFor},
				Chain:           "not-an-ip, 10.0.0.1",
				ExtractedIP:     "not-an-ip",
				Index:           0,
				TrustedProxies:  1,
			},
			want: `x_forwarded_for: invalid or implausible IP address (chain="not-an-ip, 10.0.0.1", extracted_ip="not-an-ip", index=0, trusted_proxies=1)`,
		},
		{
			name: "InvalidIPError with extracted IP only",
			err: &InvalidIPError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceXRealIP},
				ExtractedIP:     "not-an-ip",
			},
			want: `x_real_ip: invalid or implausible IP address (ip="not-an-ip")`,
		},
		{
			name: "InvalidIPError falls back to ExtractionError formatting",
			err: &InvalidIPError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
			},
			want: "remote_addr: invalid or implausible IP address",
		},
		{
			name: "RemoteAddrError",
			err: &RemoteAddrError{
				ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr},
				RemoteAddr:      "bad-remote-addr",
			},
			want: `remote_addr: invalid or implausible IP address (remote_addr="bad-remote-addr")`,
		},
		{
			name: "ChainTooLongError",
			err: &ChainTooLongError{
				ExtractionError: ExtractionError{Err: ErrChainTooLong, Source: SourceForwarded},
				ChainLength:     6,
				MaxLength:       5,
			},
			want: "forwarded: proxy chain too long (chain_length=6, max_length=5)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, tt.err.Error()); diff != "" {
				t.Fatalf("error string mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestSource_StringAndCanonicalization(t *testing.T) {
	tests := []struct {
		name string
		got  Source
		want Source
		text string
	}{
		{name: "forwarded alias", got: HeaderSource("Forwarded"), want: SourceForwarded, text: "forwarded"},
		{name: "xff alias", got: HeaderSource("X-Forwarded-For"), want: SourceXForwardedFor, text: "x_forwarded_for"},
		{name: "x-real-ip alias", got: HeaderSource("X_Real_IP"), want: SourceXRealIP, text: "x_real_ip"},
		{name: "remote addr alias", got: HeaderSource("Remote-Addr"), want: SourceRemoteAddr, text: "remote_addr"},
		{name: "custom header", got: HeaderSource("CF-Connecting-IP"), want: HeaderSource("cf-connecting-ip"), text: "cf_connecting_ip"},
		{name: "blank header invalid", got: HeaderSource("  "), want: Source{}, text: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got, want := tt.got, tt.want; got != want {
				t.Fatalf("source mismatch: got %q, want %q", got, want)
			}

			if got, want := tt.got.String(), tt.text; got != want {
				t.Fatalf("String() = %q, want %q", got, want)
			}
		})
	}
}

func TestSource_TextAndJSONRoundTrip(t *testing.T) {
	original := HeaderSource("CF-Connecting-IP")

	text, err := original.MarshalText()
	if err != nil {
		t.Fatalf("MarshalText() error = %v", err)
	}
	if got, want := string(text), "Cf-Connecting-Ip"; got != want {
		t.Fatalf("MarshalText() = %q, want %q", got, want)
	}

	var fromText Source
	if err := fromText.UnmarshalText(text); err != nil {
		t.Fatalf("UnmarshalText() error = %v", err)
	}
	if got, want := fromText, original; got != want {
		t.Fatalf("UnmarshalText() = %q, want %q", got, want)
	}

	encoded, err := json.Marshal(struct {
		Source Source `json:"source"`
	}{Source: original})
	if err != nil {
		t.Fatalf("json.Marshal() error = %v", err)
	}
	if got, want := string(encoded), `{"source":"Cf-Connecting-Ip"}`; got != want {
		t.Fatalf("json.Marshal() = %q, want %q", got, want)
	}

	var decoded struct {
		Source Source `json:"source"`
	}
	if err := json.Unmarshal(encoded, &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := decoded.Source, original; got != want {
		t.Fatalf("json.Unmarshal() source = %q, want %q", got, want)
	}

	if err := json.Unmarshal([]byte(`{"source":"X-Forwarded-For"}`), &decoded); err != nil {
		t.Fatalf("json.Unmarshal() error = %v", err)
	}
	if got, want := decoded.Source, SourceXForwardedFor; got != want {
		t.Fatalf("json.Unmarshal() source = %q, want %q", got, want)
	}
}

func TestSource_BuiltinsIgnoreExportedValueMutation(t *testing.T) {
	originalForwarded := SourceForwarded
	originalXForwardedFor := SourceXForwardedFor
	originalXRealIP := SourceXRealIP
	originalRemoteAddr := SourceRemoteAddr

	t.Cleanup(func() {
		SourceForwarded = originalForwarded
		SourceXForwardedFor = originalXForwardedFor
		SourceXRealIP = originalXRealIP
		SourceRemoteAddr = originalRemoteAddr
	})

	SourceForwarded = HeaderSource("X-Mutated-Forwarded")
	SourceXForwardedFor = HeaderSource("X-Mutated-X-Forwarded-For")
	SourceXRealIP = HeaderSource("X-Mutated-X-Real-IP")
	SourceRemoteAddr = HeaderSource("X-Mutated-Remote-Addr")

	if got, want := HeaderSource("Forwarded"), builtinSource(sourceForwarded); got != want {
		t.Fatalf("HeaderSource(Forwarded) = %q, want %q", got, want)
	}
	if got, want := HeaderSource("X-Forwarded-For"), builtinSource(sourceXForwardedFor); got != want {
		t.Fatalf("HeaderSource(X-Forwarded-For) = %q, want %q", got, want)
	}
	if got, want := HeaderSource("X-Real-IP"), builtinSource(sourceXRealIP); got != want {
		t.Fatalf("HeaderSource(X-Real-IP) = %q, want %q", got, want)
	}
	if got, want := HeaderSource("Remote-Addr"), builtinSource(sourceRemoteAddr); got != want {
		t.Fatalf("HeaderSource(Remote-Addr) = %q, want %q", got, want)
	}

	extractor := mustNewExtractor(t)
	if diff := cmp.Diff([]Source{builtinSource(sourceRemoteAddr)}, extractor.config.sourcePriority); diff != "" {
		t.Fatalf("default source priority mismatch (-want +got):\n%s", diff)
	}

	forwardedExtractor := mustNewExtractor(t,
		WithTrustedLoopbackProxy(),
		WithSourcePriority(HeaderSource("Forwarded")),
	)
	if diff := cmp.Diff([]Source{builtinSource(sourceForwarded)}, forwardedExtractor.config.sourcePriority); diff != "" {
		t.Fatalf("canonicalized source priority mismatch (-want +got):\n%s", diff)
	}
}

package clientip

import (
	"net/netip"
	"testing"
)

func TestParseIP(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    netip.Addr
		wantErr bool
	}{
		{
			name:  "valid IPv4",
			input: "203.0.113.1",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with leading whitespace",
			input: "  203.0.113.1",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with trailing whitespace",
			input: "203.0.113.1  ",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with surrounding whitespace",
			input: "  203.0.113.1  ",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with tabs",
			input: "\t203.0.113.1\t",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with port",
			input: "203.0.113.1:8080",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with double quotes",
			input: `"203.0.113.1"`,
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with single quotes",
			input: "'203.0.113.1'",
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv4 with quotes and port",
			input: `"203.0.113.1:8080"`,
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "valid IPv6",
			input: "2001:db8::1",
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		{
			name:  "valid IPv6 with brackets",
			input: "[2001:db8::1]",
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		{
			name:  "valid IPv6 with brackets and port",
			input: "[2001:db8::1]:8080",
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		{
			name:  "valid IPv6 with whitespace and brackets",
			input: "  [2001:db8::1]  ",
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		{
			name:  "localhost IPv4",
			input: "127.0.0.1",
			want:  netip.MustParseAddr("127.0.0.1"),
		},
		{
			name:  "localhost IPv4 with port",
			input: "127.0.0.1:8080",
			want:  netip.MustParseAddr("127.0.0.1"),
		},
		{
			name:  "localhost IPv6",
			input: "::1",
			want:  netip.MustParseAddr("::1"),
		},
		{
			name:  "localhost IPv6 with brackets and port",
			input: "[::1]:8080",
			want:  netip.MustParseAddr("::1"),
		},
		{
			name:    "empty string",
			input:   "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			input:   "   ",
			wantErr: true,
		},
		{
			name:    "quotes only",
			input:   `""`,
			wantErr: true,
		},
		{
			name:    "unmatched leading double quote",
			input:   `"203.0.113.1`,
			wantErr: true,
		},
		{
			name:    "unmatched trailing double quote",
			input:   `203.0.113.1"`,
			wantErr: true,
		},
		{
			name:    "unmatched leading single quote",
			input:   `'203.0.113.1`,
			wantErr: true,
		},
		{
			name:    "unmatched trailing single quote",
			input:   `203.0.113.1'`,
			wantErr: true,
		},
		{
			name:    "invalid IP",
			input:   "not-an-ip",
			wantErr: true,
		},
		{
			name:    "invalid IPv4",
			input:   "999.999.999.999",
			wantErr: true,
		},
		{
			name:    "port only",
			input:   ":8080",
			wantErr: true,
		},
		{
			name:    "brackets only",
			input:   "[]",
			wantErr: true,
		},
		{
			name:    "unmatched leading bracket",
			input:   "[2001:db8::1",
			wantErr: true,
		},
		{
			name:    "unmatched trailing bracket",
			input:   "2001:db8::1]",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseIP(tt.input)
			if tt.wantErr {
				if got.IsValid() {
					t.Errorf("parseIP(%q) = %v, want invalid", tt.input, got)
				}
			} else {
				if !got.IsValid() {
					t.Errorf("parseIP(%q) = invalid, want %v", tt.input, tt.want)
					return
				}
				if got != tt.want {
					t.Errorf("parseIP(%q) = %v, want %v", tt.input, got, tt.want)
				}
			}
		})
	}
}

func TestTrimMatchedChar(t *testing.T) {
	tests := []struct {
		name  string
		input string
		ch    byte
		want  string
	}{
		{
			name:  "matching double quote delimiter",
			input: `"203.0.113.1"`,
			ch:    '"',
			want:  "203.0.113.1",
		},
		{
			name:  "matching single quote delimiter",
			input: "'203.0.113.1'",
			ch:    '\'',
			want:  "203.0.113.1",
		},
		{
			name:  "non-matching delimiter",
			input: "203.0.113.1",
			ch:    '"',
			want:  "203.0.113.1",
		},
		{
			name:  "too short to trim",
			input: `"`,
			ch:    '"',
			want:  `"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimMatchedChar(tt.input, tt.ch)
			if got != tt.want {
				t.Errorf("trimMatchedChar(%q, %q) = %q, want %q", tt.input, tt.ch, got, tt.want)
			}
		})
	}
}

func TestTrimMatchedPair(t *testing.T) {
	tests := []struct {
		name  string
		input string
		start byte
		end   byte
		want  string
	}{
		{
			name:  "matching pair",
			input: "[2001:db8::1]",
			start: '[',
			end:   ']',
			want:  "2001:db8::1",
		},
		{
			name:  "unmatched leading bracket",
			input: "[2001:db8::1",
			start: '[',
			end:   ']',
			want:  "[2001:db8::1",
		},
		{
			name:  "unmatched trailing bracket",
			input: "2001:db8::1]",
			start: '[',
			end:   ']',
			want:  "2001:db8::1]",
		},
		{
			name:  "too short to trim",
			input: "[",
			start: '[',
			end:   ']',
			want:  "[",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := trimMatchedPair(tt.input, tt.start, tt.end)
			if got != tt.want {
				t.Errorf("trimMatchedPair(%q, %q, %q) = %q, want %q", tt.input, tt.start, tt.end, got, tt.want)
			}
		})
	}
}

func TestNormalizeIP(t *testing.T) {
	tests := []struct {
		name  string
		input netip.Addr
		want  netip.Addr
	}{
		{
			name:  "IPv4 - no change",
			input: netip.MustParseAddr("203.0.113.1"),
			want:  netip.MustParseAddr("203.0.113.1"),
		},
		{
			name:  "IPv6 - no change",
			input: netip.MustParseAddr("2001:db8::1"),
			want:  netip.MustParseAddr("2001:db8::1"),
		},
		{
			name:  "IPv4-mapped IPv6 - unmapped",
			input: netip.AddrFrom16([16]byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff, 203, 0, 113, 1}),
			want:  netip.MustParseAddr("203.0.113.1"),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := normalizeIP(tt.input)
			if got != tt.want {
				t.Errorf("normalizeIP(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

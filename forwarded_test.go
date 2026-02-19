package clientip

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseForwardedValues(t *testing.T) {
	tests := []struct {
		name    string
		values  []string
		want    []string
		wantErr error
	}{
		{
			name:   "single for value",
			values: []string{"for=1.1.1.1"},
			want:   []string{"1.1.1.1"},
		},
		{
			name:   "case-insensitive parameter name",
			values: []string{"For=1.1.1.1"},
			want:   []string{"1.1.1.1"},
		},
		{
			name:   "multiple elements in one header",
			values: []string{"for=1.1.1.1, for=8.8.8.8"},
			want:   []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:   "multiple header lines",
			values: []string{"for=1.1.1.1", "for=8.8.8.8"},
			want:   []string{"1.1.1.1", "8.8.8.8"},
		},
		{
			name:   "parameters with semicolons",
			values: []string{"for=1.1.1.1;proto=https;by=10.0.0.1"},
			want:   []string{"1.1.1.1"},
		},
		{
			name:   "quoted IPv6 and port",
			values: []string{"for=\"[2606:4700:4700::1]:8080\""},
			want:   []string{"[2606:4700:4700::1]:8080"},
		},
		{
			name:   "quoted comma is not treated as element delimiter",
			values: []string{"for=\"1.1.1.1,8.8.8.8\";proto=https"},
			want:   []string{"1.1.1.1,8.8.8.8"},
		},
		{
			name:   "quoted semicolon is not treated as param delimiter",
			values: []string{"for=\"1.1.1.1;edge\";proto=https"},
			want:   []string{"1.1.1.1;edge"},
		},
		{
			name:   "escaped quote remains inside quoted value",
			values: []string{`for="1.1.1.1\";edge";proto=https`},
			want:   []string{`1.1.1.1";edge`},
		},
		{
			name:   "ignores element without for parameter",
			values: []string{"proto=https;by=10.0.0.1, for=8.8.8.8"},
			want:   []string{"8.8.8.8"},
		},
		{
			name:    "invalid parameter format",
			values:  []string{"for"},
			wantErr: ErrInvalidForwardedHeader,
		},
		{
			name:    "unterminated quoted string",
			values:  []string{"for=\"1.1.1.1"},
			wantErr: ErrInvalidForwardedHeader,
		},
		{
			name:    "duplicate for parameter",
			values:  []string{"for=1.1.1.1;for=8.8.8.8"},
			wantErr: ErrInvalidForwardedHeader,
		},
		{
			name:    "trailing escape in quoted value",
			values:  []string{`for="1.1.1.1\`},
			wantErr: ErrInvalidForwardedHeader,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor := mustNewExtractor(t)
			got, err := extractor.parseForwardedValues(tt.values)

			if tt.wantErr != nil {
				if !errorContains(err, tt.wantErr) {
					t.Fatalf("parseForwardedValues() error = %v, want %v", err, tt.wantErr)
				}
				return
			}

			if err != nil {
				t.Fatalf("parseForwardedValues() error = %v, want nil", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("parseForwardedValues() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseForwardedValues_MaxChainLength(t *testing.T) {
	extractor := mustNewExtractor(t, MaxChainLength(2))

	_, err := extractor.parseForwardedValues([]string{"for=1.1.1.1, for=2.2.2.2, for=3.3.3.3"})
	if !errorContains(err, ErrChainTooLong) {
		t.Fatalf("parseForwardedValues() error = %v, want ErrChainTooLong", err)
	}
}

func TestParseForwardedValues_MalformedParameterMatrix(t *testing.T) {
	extractor := mustNewExtractor(t)

	tests := []struct {
		name   string
		values []string
	}{
		{name: "empty parameter key", values: []string{"=1.1.1.1"}},
		{name: "empty for value", values: []string{"for="}},
		{name: "empty quoted for value", values: []string{`for=""`}},
		{name: "invalid quoted for value suffix", values: []string{`for="1.1.1.1"extra`}},
		{name: "non for parameter missing equals", values: []string{"for=1.1.1.1;proto"}},
		{name: "non for parameter empty key", values: []string{"for=1.1.1.1;=https"}},
		{name: "non for parameter empty value", values: []string{"for=1.1.1.1;proto="}},
		{name: "unterminated quoted value across params", values: []string{"for=1.1.1.1;proto=\"https"}},
		{name: "unbalanced quotes in element", values: []string{`for="a"b"`}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, parseErr := extractor.parseForwardedValues(tt.values)

			got := struct {
				HasErr    bool
				IsInvalid bool
			}{
				HasErr:    parseErr != nil,
				IsInvalid: errorContains(parseErr, ErrInvalidForwardedHeader),
			}

			want := struct {
				HasErr    bool
				IsInvalid bool
			}{
				HasErr:    true,
				IsInvalid: true,
			}

			if diff := cmp.Diff(want, got); diff != "" {
				t.Fatalf("parseForwardedValues() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseForwardedForValue(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    string
		wantErr bool
	}{
		{name: "unquoted token", input: "1.1.1.1", want: "1.1.1.1"},
		{name: "quoted token", input: `"1.1.1.1"`, want: "1.1.1.1"},
		{name: "quoted token with surrounding spaces", input: `  "1.1.1.1"  `, want: "1.1.1.1"},
		{name: "escaped quote in quoted token", input: `"1.1.1.1\\\"edge"`, want: `1.1.1.1\"edge`},
		{name: "empty input", input: "", wantErr: true},
		{name: "spaces only", input: "  ", wantErr: true},
		{name: "unterminated quote", input: `"1.1.1.1`, wantErr: true},
		{name: "unexpected inner quote", input: `"a"b"`, wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseForwardedForValue(tt.input)

			gotView := struct {
				Value  string
				HasErr bool
			}{
				Value:  got,
				HasErr: err != nil,
			}
			wantView := struct {
				Value  string
				HasErr bool
			}{
				Value:  tt.want,
				HasErr: tt.wantErr,
			}

			if diff := cmp.Diff(wantView, gotView); diff != "" {
				t.Fatalf("parseForwardedForValue() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			extractor, _ := New()
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
				t.Errorf("parseForwardedValues() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseForwardedValues_MaxChainLength(t *testing.T) {
	extractor, err := New(MaxChainLength(2))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = extractor.parseForwardedValues([]string{"for=1.1.1.1, for=2.2.2.2, for=3.3.3.3"})
	if !errorContains(err, ErrChainTooLong) {
		t.Errorf("parseForwardedValues() error = %v, want ErrChainTooLong", err)
	}
}

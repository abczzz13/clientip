package clientip

import (
	"errors"
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestParseXFFValues(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []string
	}{
		{name: "single value", values: []string{"1.1.1.1"}, want: []string{"1.1.1.1"}},
		{name: "single value with multiple IPs", values: []string{"1.1.1.1, 8.8.8.8"}, want: []string{"1.1.1.1", "8.8.8.8"}},
		{name: "multiple values combined", values: []string{"1.1.1.1", "8.8.8.8"}, want: []string{"1.1.1.1", "8.8.8.8"}},
		{name: "whitespace trimmed", values: []string{"  1.1.1.1  ,  8.8.8.8  "}, want: []string{"1.1.1.1", "8.8.8.8"}},
		{name: "empty strings ignored", values: []string{"1.1.1.1, , 8.8.8.8"}, want: []string{"1.1.1.1", "8.8.8.8"}},
		{name: "empty list", values: []string{}, want: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := parseXFFValues(tt.values, 100)
			if err != nil {
				t.Fatalf("parseXFFValues() error = %v, want nil", err)
			}

			if diff := cmp.Diff(tt.want, got); diff != "" {
				t.Fatalf("parseXFFValues() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

func TestParseXFFValues_MaxChainLength(t *testing.T) {
	_, err := parseXFFValues([]string{"1.1.1.1, 2.2.2.2, 3.3.3.3, 4.4.4.4, 5.5.5.5, 6.6.6.6, 7.7.7.7"}, 5)

	var chainErr *chainTooLongParseError
	if !errors.As(err, &chainErr) {
		t.Fatalf("parseXFFValues() error = %v, want chainTooLongParseError", err)
	}
}

func TestParseXFFValues_PreservesWireOrderAcrossHeaderLines(t *testing.T) {
	values := []string{"1.1.1.1, 8.8.8.8", "9.9.9.9", " 4.4.4.4 , 5.5.5.5 "}

	got, err := parseXFFValues(values, 10)
	if err != nil {
		t.Fatalf("parseXFFValues() error = %v", err)
	}

	want := []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "4.4.4.4", "5.5.5.5"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("parseXFFValues() mismatch (-want +got):\n%s", diff)
	}
}

func TestParseXFFValues_MaxChainLength_AcrossHeaderLines(t *testing.T) {
	_, err := parseXFFValues([]string{"1.1.1.1, 8.8.8.8", "9.9.9.9", "4.4.4.4"}, 3)

	var chainErr *chainTooLongParseError
	if !errors.As(err, &chainErr) {
		t.Fatalf("parseXFFValues() error = %v, want chainTooLongParseError", err)
	}
}

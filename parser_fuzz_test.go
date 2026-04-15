package clientip

import (
	"errors"
	"testing"
)

func FuzzParseIP_RoundTripNormalization(f *testing.F) {
	for _, seed := range []string{
		"1.1.1.1",
		"  1.1.1.1  ",
		"1.1.1.1:443",
		"[2606:4700:4700::1]:443",
		`"1.1.1.1"`,
		`'1.1.1.1'`,
		"not-an-ip",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		parsed := parseIP(raw)
		if !parsed.IsValid() {
			return
		}

		roundTrip := parseIP(parsed.String())
		if !roundTrip.IsValid() {
			t.Fatalf("round-trip parse invalid for %q (%q)", raw, parsed.String())
		}

		if normalizeIP(parsed) != normalizeIP(roundTrip) {
			t.Fatalf("normalized round-trip mismatch for %q", raw)
		}
	})
}

func FuzzParseRemoteAddr_RoundTripNormalization(f *testing.F) {
	for _, seed := range []string{
		"1.1.1.1:443",
		"[2606:4700:4700::1]:443",
		"1.1.1.1",
		"2606:4700:4700::1",
		"example.com:443",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		parsed := parseRemoteAddr(raw)
		if !parsed.IsValid() {
			return
		}

		roundTrip := parseIP(parsed.String())
		if !roundTrip.IsValid() {
			t.Fatalf("round-trip parse invalid for remote addr %q (%q)", raw, parsed.String())
		}

		if normalizeIP(parsed) != normalizeIP(roundTrip) {
			t.Fatalf("normalized round-trip mismatch for remote addr %q", raw)
		}
	})
}

func FuzzParseXFFValues_ErrorShapeAndOutput(f *testing.F) {
	extractor, err := New(MaxChainLength(16))
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}

	for _, seed := range []string{
		"1.1.1.1",
		"1.1.1.1, 8.8.8.8",
		"1.1.1.1, , 8.8.8.8",
		"\t1.1.1.1\t",
		",",
		", ,",
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		valueSets := [][]string{
			{raw},
			{raw, raw},
			{"1.1.1.1", raw},
			{raw, "8.8.8.8"},
		}

		for _, values := range valueSets {
			parts, parseErr := extractor.parseXFFValues(values)

			if parseErr != nil {
				if !errors.Is(parseErr, ErrChainTooLong) {
					t.Fatalf("unexpected parseXFFValues error type for %#v: %v", values, parseErr)
				}
				continue
			}

			if len(parts) > extractor.config.maxChainLength {
				t.Fatalf("parts length = %d, max = %d", len(parts), extractor.config.maxChainLength)
			}

			for i, part := range parts {
				if part == "" {
					t.Fatalf("empty part at index %d", i)
				}
				if part != trimHTTPWhitespace(part) {
					t.Fatalf("part has untrimmed HTTP whitespace at index %d: %q", i, part)
				}
			}
		}
	})
}

func FuzzParseForwardedValues_ErrorShapeAndOutput(f *testing.F) {
	extractor, err := New(MaxChainLength(16))
	if err != nil {
		f.Fatalf("New() error = %v", err)
	}

	for _, seed := range []string{
		"for=1.1.1.1",
		"for=1.1.1.1, for=8.8.8.8",
		"for=1.1.1.1;proto=https",
		`for="[2606:4700:4700::1]:443"`,
		`for="1.1.1.1\"edge"`,
		"for",
		`for="unterminated`,
		"",
	} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		valueSets := [][]string{
			{raw},
			{raw, raw},
			{"for=1.1.1.1", raw},
			{raw, "for=8.8.8.8"},
		}

		for _, values := range valueSets {
			parts, parseErr := extractor.parseForwardedValues(values)

			if parseErr != nil {
				if !errors.Is(parseErr, ErrInvalidForwardedHeader) && !errors.Is(parseErr, ErrChainTooLong) {
					t.Fatalf("unexpected parseForwardedValues error type for %#v: %v", values, parseErr)
				}
				continue
			}

			if len(parts) > extractor.config.maxChainLength {
				t.Fatalf("parts length = %d, max = %d", len(parts), extractor.config.maxChainLength)
			}

			for i, part := range parts {
				if part == "" {
					t.Fatalf("empty forwarded part at index %d", i)
				}
			}
		}
	})
}

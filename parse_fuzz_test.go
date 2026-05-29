package clientip

import (
	"errors"
	"os"
	"strconv"
	"testing"
)

// defaultFuzzMaxHeaderValueLen keeps PR fuzz smoke near common proxy/request
// header limits. Typical defaults range from about 8-16 KiB per field to around
// 60-64 KiB total headers, while Go's net/http default total header cap is 1
// MiB. Use 64 KiB by default so PR fuzzing still covers realistic high-end
// proxy inputs without spending CI time on oversized strings. Deep fuzzing can
// raise this with CLIENTIP_FUZZ_MAX_HEADER_VALUE_LEN.
const defaultFuzzMaxHeaderValueLen = 64 * 1024

var fuzzMaxHeaderValueLen = configuredFuzzMaxHeaderValueLen()

func configuredFuzzMaxHeaderValueLen() int {
	raw := os.Getenv("CLIENTIP_FUZZ_MAX_HEADER_VALUE_LEN")
	if raw == "" {
		return defaultFuzzMaxHeaderValueLen
	}

	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 {
		panic("CLIENTIP_FUZZ_MAX_HEADER_VALUE_LEN must be a positive integer byte count")
	}
	return n
}

func skipOversizedFuzzInput(t *testing.T, raw string) {
	t.Helper()
	if len(raw) > fuzzMaxHeaderValueLen {
		t.Skipf("skipping oversized fuzz input with %d bytes", len(raw))
	}
}

func FuzzParseIP_RoundTripNormalization(f *testing.F) {
	for _, seed := range []string{"1.1.1.1", "  1.1.1.1  ", "1.1.1.1:443", "[2606:4700:4700::1]:443", `"1.1.1.1"`, `'1.1.1.1'`, "not-an-ip", ""} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		skipOversizedFuzzInput(t, raw)

		parsed := parseIP(raw)
		if !parsed.IsValid() {
			return
		}

		roundTrip := parseIP(parsed.String())
		if !roundTrip.IsValid() {
			t.Fatalf("round-trip parse invalid for %q (%q)", raw, parsed.String())
		}

		if parsed.Unmap() != roundTrip.Unmap() {
			t.Fatalf("normalized round-trip mismatch for %q", raw)
		}
	})
}

func FuzzParseRemoteAddr_RoundTripNormalization(f *testing.F) {
	for _, seed := range []string{"1.1.1.1:443", "[2606:4700:4700::1]:443", "1.1.1.1", "2606:4700:4700::1", "example.com:443", ""} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		skipOversizedFuzzInput(t, raw)

		parsed := parseRemoteAddr(raw)
		if !parsed.IsValid() {
			return
		}

		roundTrip := parseIP(parsed.String())
		if !roundTrip.IsValid() {
			t.Fatalf("round-trip parse invalid for remote addr %q (%q)", raw, parsed.String())
		}

		if parsed.Unmap() != roundTrip.Unmap() {
			t.Fatalf("normalized round-trip mismatch for remote addr %q", raw)
		}
	})
}

func FuzzParseXFFValues_ErrorShapeAndOutput(f *testing.F) {
	for _, seed := range []string{"1.1.1.1", "1.1.1.1, 8.8.8.8", "1.1.1.1, , 8.8.8.8", "\t1.1.1.1\t", ",", ", ,", ""} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		skipOversizedFuzzInput(t, raw)

		valueSets := [][]string{{raw}, {raw, raw}, {"1.1.1.1", raw}, {raw, "8.8.8.8"}}

		for _, values := range valueSets {
			parts, parseErr := parseXFFValues(values, 16)

			if parseErr != nil {
				var chainErr *chainTooLongParseError
				if !errors.As(parseErr, &chainErr) {
					t.Fatalf("unexpected parseXFFValues error type for %#v: %v", values, parseErr)
				}
				continue
			}

			if len(parts) > 16 {
				t.Fatalf("parts length = %d, max = %d", len(parts), 16)
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
	for _, seed := range []string{"for=1.1.1.1", "for=1.1.1.1, for=8.8.8.8", "for=1.1.1.1;proto=https", `for="[2606:4700:4700::1]:443"`, `for="1.1.1.1\"edge"`, "for", `for="unterminated`, "", "   ", ",for=1.1.1.1", "for=1.1.1.1,", "for=1.1.1.1,,for=8.8.8.8", ";for=1.1.1.1", "for=1.1.1.1;", "for=1.1.1.1;;proto=https"} {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, raw string) {
		skipOversizedFuzzInput(t, raw)

		valueSets := [][]string{{raw}, {raw, raw}, {"for=1.1.1.1", raw}, {raw, "for=8.8.8.8"}}

		for _, values := range valueSets {
			parts, parseErr := parseForwardedValues(values, 16)

			if parseErr != nil {
				var chainErr *chainTooLongParseError
				if errors.As(parseErr, &chainErr) {
					continue
				}
				continue
			}

			if len(parts) > 16 {
				t.Fatalf("parts length = %d, max = %d", len(parts), 16)
			}

			for i, part := range parts {
				if part == "" {
					t.Fatalf("empty forwarded part at index %d", i)
				}
			}
		}
	})
}

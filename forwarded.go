package clientip

import (
	"errors"
	"fmt"
	"strings"
)

// parseForwardedValues extracts the Forwarded for= chain from one or more
// Forwarded header values.
//
// Header values and elements are processed in wire order. Elements without a
// for parameter are ignored. Any parse failure is converted to an
// ErrInvalidForwardedHeader extraction error with SourceForwarded.
//
// The returned chain is bounded by the configured maxChainLength.
func (e *Extractor) parseForwardedValues(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	parts := make([]string, 0, typicalChainCapacity)

	for _, value := range values {
		err := scanForwardedSegments(value, ',', func(element string) error {
			forwardedFor, hasFor, parseErr := parseForwardedElement(element)
			if parseErr != nil {
				return parseErr
			}
			if !hasFor {
				return nil
			}

			var appendErr error
			parts, appendErr = e.appendChainPart(parts, forwardedFor, SourceForwarded)
			return appendErr
		})
		if err != nil {
			if errors.Is(err, ErrChainTooLong) {
				return nil, err
			}

			return nil, invalidForwardedHeaderError(err)
		}
	}

	return parts, nil
}

// invalidForwardedHeaderError wraps low-level parse errors as an extraction
// error tagged with ErrInvalidForwardedHeader and SourceForwarded.
func invalidForwardedHeaderError(err error) error {
	return &ExtractionError{
		Err:    fmt.Errorf("%w: %w", ErrInvalidForwardedHeader, err),
		Source: SourceForwarded,
	}
}

// parseForwardedElement parses a single Forwarded element and returns its for
// parameter value when present.
//
// It allows arbitrary additional parameters, treats the parameter name
// case-insensitively, and rejects duplicate for parameters in the same
// element.
func parseForwardedElement(element string) (forwardedFor string, hasFor bool, err error) {
	err = scanForwardedSegments(element, ';', func(param string) error {
		eq := strings.IndexByte(param, '=')
		if eq <= 0 {
			return fmt.Errorf("invalid forwarded parameter %q", param)
		}

		key := strings.TrimSpace(param[:eq])
		value := strings.TrimSpace(param[eq+1:])
		if key == "" {
			return fmt.Errorf("empty parameter key in %q", param)
		}
		if value == "" {
			return fmt.Errorf("empty parameter value for %q", key)
		}

		if !strings.EqualFold(key, "for") {
			return nil
		}

		if hasFor {
			return fmt.Errorf("duplicate for parameter in element %q", element)
		}

		parsedValue, parseErr := parseForwardedForValue(value)
		if parseErr != nil {
			return parseErr
		}

		forwardedFor = parsedValue
		hasFor = true
		return nil
	})
	if err != nil {
		return "", false, err
	}

	return forwardedFor, hasFor, nil
}

// scanForwardedSegments splits value by delimiter while respecting quoted
// segments and escape sequences inside quoted strings.
func scanForwardedSegments(value string, delimiter byte, onSegment func(string) error) error {
	start := 0
	inQuotes := false
	escaped := false

	for i := 0; i <= len(value); i++ {
		if i == len(value) {
			if inQuotes {
				return fmt.Errorf("unterminated quoted string in %q", value)
			}
			if escaped {
				return fmt.Errorf("unterminated escape in %q", value)
			}
		} else {
			ch := value[i]

			if escaped {
				escaped = false
				continue
			}

			if ch == '\\' && inQuotes {
				escaped = true
				continue
			}

			if ch == '"' {
				inQuotes = !inQuotes
				continue
			}

			if ch != delimiter || inQuotes {
				continue
			}
		}

		segment := strings.TrimSpace(value[start:i])
		if segment != "" {
			if err := onSegment(segment); err != nil {
				return err
			}
		}

		start = i + 1
	}

	return nil
}

// parseForwardedForValue parses a Forwarded for parameter value.
//
// The value may be an unquoted token or a quoted string. For quoted strings,
// escaping is handled by unquoteForwardedValue.
func parseForwardedForValue(value string) (string, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return "", fmt.Errorf("empty for value")
	}

	if value[0] == '"' {
		unquoted, err := unquoteForwardedValue(value)
		if err != nil {
			return "", err
		}
		value = strings.TrimSpace(unquoted)
	}

	if value == "" {
		return "", fmt.Errorf("empty for value")
	}

	return value, nil
}

// unquoteForwardedValue removes surrounding quotes from a Forwarded quoted
// string and resolves backslash escapes.
func unquoteForwardedValue(value string) (string, error) {
	if len(value) < 2 || value[0] != '"' || value[len(value)-1] != '"' {
		return "", fmt.Errorf("invalid quoted string %q", value)
	}

	inner := value[1 : len(value)-1]
	if strings.IndexByte(inner, '\\') == -1 {
		if strings.IndexByte(inner, '"') != -1 {
			return "", fmt.Errorf("unexpected quote in %q", value)
		}

		return inner, nil
	}

	var b strings.Builder
	b.Grow(len(inner))
	escaped := false

	for i := 1; i < len(value)-1; i++ {
		ch := value[i]

		if escaped {
			b.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' {
			escaped = true
			continue
		}

		if ch == '"' {
			return "", fmt.Errorf("unexpected quote in %q", value)
		}

		b.WriteByte(ch)
	}

	if escaped {
		return "", fmt.Errorf("unterminated escape in %q", value)
	}

	return b.String(), nil
}

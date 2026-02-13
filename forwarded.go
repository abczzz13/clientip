package clientip

import (
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
		elements, err := splitForwardedHeaderValue(value, ',')
		if err != nil {
			return nil, invalidForwardedHeaderError(err)
		}

		for _, element := range elements {
			element = strings.TrimSpace(element)
			if element == "" {
				continue
			}

			forwardedFor, hasFor, err := parseForwardedElement(element)
			if err != nil {
				return nil, invalidForwardedHeaderError(err)
			}
			if !hasFor {
				continue
			}

			parts, err = e.appendChainPart(parts, forwardedFor, SourceForwarded)
			if err != nil {
				return nil, err
			}
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
	params, err := splitForwardedHeaderValue(element, ';')
	if err != nil {
		return "", false, err
	}

	for _, param := range params {
		param = strings.TrimSpace(param)
		if param == "" {
			continue
		}

		eq := strings.IndexByte(param, '=')
		if eq <= 0 {
			return "", false, fmt.Errorf("invalid forwarded parameter %q", param)
		}

		key := strings.TrimSpace(param[:eq])
		value := strings.TrimSpace(param[eq+1:])
		if key == "" {
			return "", false, fmt.Errorf("empty parameter key in %q", param)
		}
		if value == "" {
			return "", false, fmt.Errorf("empty parameter value for %q", key)
		}

		if !strings.EqualFold(key, "for") {
			continue
		}

		if hasFor {
			return "", false, fmt.Errorf("duplicate for parameter in element %q", element)
		}

		parsedValue, parseErr := parseForwardedForValue(value)
		if parseErr != nil {
			return "", false, parseErr
		}

		forwardedFor = parsedValue
		hasFor = true
	}

	return forwardedFor, hasFor, nil
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

	var b strings.Builder
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

// splitForwardedHeaderValue splits value by delimiter while respecting quoted
// segments and escape sequences inside quoted strings.
func splitForwardedHeaderValue(value string, delimiter byte) ([]string, error) {
	segments := make([]string, 0, 4)
	start := 0
	inQuotes := false
	escaped := false

	for i := 0; i < len(value); i++ {
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

		if ch == delimiter && !inQuotes {
			segments = append(segments, value[start:i])
			start = i + 1
		}
	}

	if inQuotes {
		return nil, fmt.Errorf("unterminated quoted string in %q", value)
	}
	if escaped {
		return nil, fmt.Errorf("unterminated escape in %q", value)
	}

	segments = append(segments, value[start:])
	return segments, nil
}

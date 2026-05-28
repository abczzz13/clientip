package clientip

import (
	"errors"
	"fmt"
	"strings"
)

// parseForwardedValues extracts RFC 7239 for= values from repeated Forwarded
// header lines in arrival order. Only for= parameters become chain entries;
// malformed syntax fails closed because a sabotaged Forwarded header can hide
// or reorder client attribution.
func parseForwardedValues(values []string, maxChainLength int) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	parts := make([]string, 0, chainPartsCapacity(values, maxChainLength))

	for _, value := range values {
		err := scanForwardedSegments(value, ',', "element", func(element string) error {
			forwardedFor, hasFor, parseErr := parseForwardedElement(element)
			if parseErr != nil {
				return parseErr
			}
			if !hasFor {
				return nil
			}

			if len(parts) >= maxChainLength {
				return &chainTooLongParseError{
					ChainLength: len(parts) + 1,
					MaxLength:   maxChainLength,
				}
			}

			parts = append(parts, forwardedFor)
			return nil
		})
		if err != nil {
			var chainErr *chainTooLongParseError
			if errors.As(err, &chainErr) {
				return nil, err
			}

			return nil, err
		}
	}

	return parts, nil
}

// parseForwardedElement extracts at most one for= parameter from an element.
// Duplicate for= parameters are rejected as ambiguous instead of choosing one.
func parseForwardedElement(element string) (forwardedFor string, hasFor bool, err error) {
	err = scanForwardedSegments(element, ';', "parameter", func(param string) error {
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

// scanForwardedSegments splits on delimiter while respecting quoted strings
// and quoted-pair escapes. This prevents commas or semicolons inside quoted
// values from changing the element/parameter structure we validate.
func scanForwardedSegments(value string, delimiter byte, segmentKind string, onSegment func(string) error) error {
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
		if segment == "" {
			return fmt.Errorf("empty forwarded %s in %q", segmentKind, value)
		}
		if err := onSegment(segment); err != nil {
			return err
		}

		start = i + 1
	}

	return nil
}

// parseForwardedForValue normalizes the value side of for=. Quoted values must
// be fully quoted and valid; partially quoted or empty values are malformed.
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

// unquoteForwardedValue decodes a Forwarded quoted-string and rejects raw
// quotes or dangling escapes so malformed header input remains terminal.
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

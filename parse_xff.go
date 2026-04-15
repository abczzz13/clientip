package clientip

import "strings"

func parseXFFValues(values []string, maxChainLength int) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	// Fast path: single header value with no commas and no surrounding whitespace.
	// Return the input slice directly to avoid allocation.
	if len(values) == 1 {
		v := values[0]
		if strings.IndexByte(v, ',') == -1 {
			trimmed := trimHTTPWhitespace(v)
			if trimmed == "" {
				return nil, nil
			}
			if maxChainLength <= 0 {
				return nil, &chainTooLongParseError{ChainLength: 1, MaxLength: maxChainLength}
			}
			if trimmed == v {
				return values, nil
			}
			return []string{trimmed}, nil
		}
	}

	parts := make([]string, 0, chainPartsCapacity(values, maxChainLength))
	for _, v := range values {
		start := 0
		for i := 0; i <= len(v); i++ {
			if i != len(v) && v[i] != ',' {
				continue
			}

			part := trimHTTPWhitespace(v[start:i])
			if part != "" {
				if len(parts) >= maxChainLength {
					return nil, &chainTooLongParseError{
						ChainLength: len(parts) + 1,
						MaxLength:   maxChainLength,
					}
				}

				parts = append(parts, part)
			}

			start = i + 1
		}
	}

	return parts, nil
}

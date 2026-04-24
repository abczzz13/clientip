package clientip

import "strings"

const typicalChainCapacity = 8

func chainPartsCapacity(values []string, maxLength int) int {
	if maxLength <= 0 {
		maxLength = 1
	}

	if len(values) == 1 {
		v := values[0]
		firstComma := strings.IndexByte(v, ',')
		if firstComma == -1 {
			return 1
		}

		secondComma := strings.IndexByte(v[firstComma+1:], ',')
		if secondComma == -1 {
			if maxLength < 2 {
				return maxLength
			}
			return 2
		}

		if strings.IndexByte(v[firstComma+secondComma+2:], ',') == -1 {
			if maxLength < 3 {
				return maxLength
			}
			return 3
		}
	} else if len(values) == 2 {
		if strings.IndexByte(values[0], ',') == -1 && strings.IndexByte(values[1], ',') == -1 {
			if maxLength < 2 {
				return maxLength
			}
			return 2
		}
	}

	if maxLength < typicalChainCapacity {
		return maxLength
	}

	return typicalChainCapacity
}

func trimHTTPWhitespace(value string) string {
	start := 0
	for start < len(value) {
		ch := value[start]
		if ch != ' ' && ch != '\t' {
			break
		}
		start++
	}

	end := len(value)
	for end > start {
		ch := value[end-1]
		if ch != ' ' && ch != '\t' {
			break
		}
		end--
	}

	return value[start:end]
}

package clientip

import "fmt"

type chainTooLongParseError struct {
	ChainLength int
	MaxLength   int
}

func (e *chainTooLongParseError) Error() string {
	return fmt.Sprintf("proxy chain too long (chain_length=%d, max_length=%d)", e.ChainLength, e.MaxLength)
}

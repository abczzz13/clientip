package clientip

func (e *Extractor) parseXFFValues(values []string) ([]string, error) {
	if len(values) == 0 {
		return nil, nil
	}

	maxChainLength := e.config.maxChainLength
	parts := make([]string, 0, e.chainPartsCapacity(values))
	for _, v := range values {
		start := 0
		for i := 0; i <= len(v); i++ {
			if i != len(v) && v[i] != ',' {
				continue
			}

			part := trimHTTPWhitespace(v[start:i])
			if part != "" {
				if len(parts) >= maxChainLength {
					e.config.metrics.RecordSecurityEvent(securityEventChainTooLong)
					return nil, &ChainTooLongError{
						ExtractionError: ExtractionError{
							Err:    ErrChainTooLong,
							Source: builtinSource(sourceXForwardedFor),
						},
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

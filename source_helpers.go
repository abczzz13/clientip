package clientip

import "errors"

func sourceUnavailableError(unavailableErr error, sourceName string) error {
	if unavailableErr != nil {
		return unavailableErr
	}

	return &ExtractionError{Err: ErrSourceUnavailable, Source: sourceName}
}

func wrapSourceUnavailableError(err, unavailableErr error, sourceName string) error {
	if !errors.Is(err, ErrSourceUnavailable) {
		return err
	}

	return sourceUnavailableError(unavailableErr, sourceName)
}

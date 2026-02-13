package clientip

import "errors"

func errorIsType(err error, target any) bool {
	if err == nil {
		return false
	}
	switch target.(type) {
	case *ExtractionError:
		var e *ExtractionError
		return asError(err, &e)
	case *MultipleHeadersError:
		var e *MultipleHeadersError
		return asError(err, &e)
	case *ProxyValidationError:
		var e *ProxyValidationError
		return asError(err, &e)
	case *InvalidIPError:
		var e *InvalidIPError
		return asError(err, &e)
	case *RemoteAddrError:
		var e *RemoteAddrError
		return asError(err, &e)
	default:
		return false
	}
}

func asError(err error, target any) bool {
	switch v := target.(type) {
	case **ExtractionError:
		return errors.As(err, v)
	case **MultipleHeadersError:
		return errors.As(err, v)
	case **ProxyValidationError:
		return errors.As(err, v)
	case **InvalidIPError:
		return errors.As(err, v)
	case **RemoteAddrError:
		return errors.As(err, v)
	default:
		return false
	}
}

func errorContains(err, target error) bool {
	if err == nil {
		return false
	}
	return errors.Is(err, target)
}

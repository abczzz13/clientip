package clientip

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

func TestClassifyError(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want ResultKind
	}{
		{name: "nil", want: ResultSuccess},
		{name: "source unavailable", err: &ExtractionError{Err: ErrSourceUnavailable, Source: SourceRemoteAddr}, want: ResultUnavailable},
		{name: "invalid ip", err: &RemoteAddrError{ExtractionError: ExtractionError{Err: ErrInvalidIP, Source: SourceRemoteAddr}, RemoteAddr: "bad"}, want: ResultInvalid},
		{name: "nil request", err: ErrNilRequest, want: ResultInvalid},
		{name: "untrusted proxy", err: &ProxyValidationError{ExtractionError: ExtractionError{Err: ErrUntrustedProxy, Source: SourceXRealIP}}, want: ResultUntrusted},
		{name: "too few trusted proxies", err: &ProxyValidationError{ExtractionError: ExtractionError{Err: ErrTooFewTrustedProxies, Source: SourceXForwardedFor}}, want: ResultUntrusted},
		{name: "malformed forwarded", err: fmt.Errorf("wrapped: %w", &ExtractionError{Err: ErrInvalidForwardedHeader, Source: SourceForwarded}), want: ResultMalformed},
		{name: "chain too long", err: &ChainTooLongError{ExtractionError: ExtractionError{Err: ErrChainTooLong, Source: SourceXForwardedFor}, ChainLength: 101, MaxLength: 100}, want: ResultMalformed},
		{name: "multiple single-ip headers", err: &MultipleHeadersError{ExtractionError: ExtractionError{Err: ErrMultipleSingleIPHeaders, Source: SourceXRealIP}, HeaderCount: 2}, want: ResultMalformed},
		{name: "canceled", err: context.Canceled, want: ResultCanceled},
		{name: "deadline exceeded", err: context.DeadlineExceeded, want: ResultCanceled},
		{name: "unknown", err: errors.New("boom"), want: ResultUnknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ClassifyError(tt.err); got != tt.want {
				t.Fatalf("ClassifyError(%v) = %v, want %v", tt.err, got, tt.want)
			}
		})
	}
}

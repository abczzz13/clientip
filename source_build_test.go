package clientip

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestCompileSpecFromSource(t *testing.T) {
	tests := []struct {
		name   string
		source Source
		want   sourceSpec
	}{
		{
			name:   "forwarded source",
			source: SourceForwarded,
			want: sourceSpec{
				kind:       sourceExtractorKindForwarded,
				source:     SourceForwarded,
				headerName: "Forwarded",
			},
		},
		{
			name:   "x forwarded for source",
			source: SourceXForwardedFor,
			want: sourceSpec{
				kind:       sourceExtractorKindXForwardedFor,
				source:     SourceXForwardedFor,
				headerName: "X-Forwarded-For",
			},
		},
		{
			name:   "x real ip source",
			source: SourceXRealIP,
			want: sourceSpec{
				kind:       sourceExtractorKindSingleHeader,
				source:     SourceXRealIP,
				headerName: "X-Real-Ip",
			},
		},
		{
			name:   "remote addr source",
			source: SourceRemoteAddr,
			want: sourceSpec{
				kind:       sourceExtractorKindRemoteAddr,
				source:     SourceRemoteAddr,
				headerName: "",
			},
		},
		{
			name:   "custom header source",
			source: HeaderSource("x-custom-header"),
			want: sourceSpec{
				kind:       sourceExtractorKindSingleHeader,
				source:     HeaderSource("X-Custom-Header"),
				headerName: "X-Custom-Header",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if diff := cmp.Diff(tt.want, compileSpecFromSource(tt.source), cmp.AllowUnexported(sourceSpec{}, Source{})); diff != "" {
				t.Fatalf("compileSpecFromSource() mismatch (-want +got):\n%s", diff)
			}
		})
	}
}

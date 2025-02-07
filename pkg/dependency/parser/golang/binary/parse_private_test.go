package binary

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestSplitLDFlags(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []string
		wantErr string
	}{
		{
			name:  "flag with single nested flag",
			input: "-extldflags '-static'",
			want: []string{
				"-extldflags",
				"'-static'",
			},
		},
		{
			name:  "flag with multiple nested flag",
			input: "-extldflags '-static -lm -ldl -lz -lpthread'",
			want: []string{
				"-extldflags",
				"'-static -lm -ldl -lz -lpthread'",
			},
		},
		{
			name:  "multiple flags with nested flag",
			input: "-extldflags '-static -lm -ldl -lz -lpthread' -s -w -extldflags '-static'",
			want: []string{
				"-extldflags",
				"'-static -lm -ldl -lz -lpthread'",
				"-s",
				"-w",
				"-extldflags",
				"'-static'",
			},
		},
		{
			name:  "without nested flags",
			input: "-s -w -X='github.com/aquasecurity/trivy/cmd/Any.Ver=0.50.0'",
			want: []string{
				"-s",
				"-w",
				"-X='github.com/aquasecurity/trivy/cmd/Any.Ver=0.50.0'",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := splitLDFlags(tt.input)
			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

package artifact

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCanonicalVersion(t *testing.T) {
	tests := []struct {
		title string
		input string
		want  string
	}{
		{
			title: "good way",
			input: "0.34.0",
			want:  "v0.34",
		},
		{
			title: "version with v - isn't right semver version",
			input: "v0.34.0",
			want:  devVersion,
		},
		{
			title: "dev version",
			input: devVersion,
			want:  devVersion,
		},
		{
			title: "pre-release",
			input: "v0.34.0-beta1+snapshot-1",
			want:  devVersion,
		},
		{
			title: "no version",
			input: "",
			want:  devVersion,
		},
	}

	for _, test := range tests {
		t.Run(test.title, func(t *testing.T) {
			got := canonicalVersion(test.input)
			require.Equal(t, test.want, got)
		})
	}
}

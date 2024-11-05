package pip

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name          string
		filePath      string
		useMinVersion bool
		want          []ftypes.Package
	}{
		{
			name:     "happy path",
			filePath: "testdata/requirements_flask.txt",
			want:     requirementsFlask,
		},
		{
			name:     "happy path with comments",
			filePath: "testdata/requirements_comments.txt",
			want:     requirementsComments,
		},
		{
			name:     "happy path with spaces",
			filePath: "testdata/requirements_spaces.txt",
			want:     requirementsSpaces,
		},
		{
			name:     "happy path with dependency without version",
			filePath: "testdata/requirements_no_version.txt",
			want:     requirementsNoVersion,
		},
		{
			name:     "happy path with operator",
			filePath: "testdata/requirements_operator.txt",
			want:     requirementsOperator,
		},
		{
			name:     "happy path with hash",
			filePath: "testdata/requirements_hash.txt",
			want:     requirementsHash,
		},
		{
			name:     "happy path with hyphens",
			filePath: "testdata/requirements_hyphens.txt",
			want:     requirementsHyphens,
		},
		{
			name:     "happy path with exstras",
			filePath: "testdata/requirement_exstras.txt",
			want:     requirementsExtras,
		},
		{
			name:     "happy path. File uses utf16le",
			filePath: "testdata/requirements_utf16le.txt",
			want:     requirementsUtf16le,
		},
		{
			name:     "happy path with templating engine",
			filePath: "testdata/requirements_with_templating_engine.txt",
			want:     nil,
		},
		{
			name:          "compatible versions",
			filePath:      "testdata/requirements_compatible.txt",
			useMinVersion: true,
			want:          requirementsCompatibleVersions,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.filePath)
			require.NoError(t, err)

			got, _, err := NewParser(tt.useMinVersion).Parse(f)
			require.NoError(t, err)

			assert.Equal(t, tt.want, got)
		})
	}
}

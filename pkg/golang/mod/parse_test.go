package mod

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name string
		file string
		want []types.Library
	}{
		{
			name: "normal",
			file: "testdata/normal/go.mod",
			want: GoModNormal,
		},
		{
			name: "without go version",
			file: "testdata/no-go-version/go.mod",
			want: GoModNoGoVersion,
		},
		{
			name: "replace",
			file: "testdata/replaced/go.mod",
			want: GoModReplaced,
		},
		{
			name: "replace with version",
			file: "testdata/replaced-with-version/go.mod",
			want: GoModReplacedWithVersion,
		},
		{
			name: "replaced with version mismatch",
			file: "testdata/replaced-with-version-mismatch/go.mod",
			want: GoModReplacedWithVersionMismatch,
		},
		{
			name: "replaced with local path",
			file: "testdata/replaced-with-local-path/go.mod",
			want: GoModReplacedWithLocalPath,
		},
		{
			name: "replaced with local path and version",
			file: "testdata/replaced-with-local-path-and-version/go.mod",
			want: GoModReplacedWithLocalPathAndVersion,
		},
		{
			name: "replaced with local path and version, mismatch",
			file: "testdata/replaced-with-local-path-and-version-mismatch/go.mod",
			want: GoModReplacedWithLocalPathAndVersionMismatch,
		},
		{
			name: "go 1.16",
			file: "testdata/go116/go.mod",
			want: GoMod116,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				return got[i].Name < got[j].Name
			})
			sort.Slice(tt.want, func(i, j int) bool {
				return tt.want[i].Name < tt.want[j].Name
			})

			assert.Equal(t, tt.want, got)
		})
	}
}

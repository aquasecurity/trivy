package mod

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		file    string
		replace bool
		want    []ftypes.Package
	}{
		{
			name:    "normal",
			file:    "testdata/normal/go.mod",
			replace: true,
			want:    GoModNormal,
		},
		{
			name:    "without go version",
			file:    "testdata/no-go-version/gomod",
			replace: true,
			want:    GoModNoGoVersion,
		},
		{
			name:    "replace",
			file:    "testdata/replaced/go.mod",
			replace: true,
			want:    GoModReplaced,
		},
		{
			name:    "no replace",
			file:    "testdata/replaced/go.mod",
			replace: false,
			want:    GoModUnreplaced,
		},
		{
			name:    "replace with version",
			file:    "testdata/replaced-with-version/go.mod",
			replace: true,
			want:    GoModReplacedWithVersion,
		},
		{
			name:    "replaced with version mismatch",
			file:    "testdata/replaced-with-version-mismatch/go.mod",
			replace: true,
			want:    GoModReplacedWithVersionMismatch,
		},
		{
			name:    "replaced with local path",
			file:    "testdata/replaced-with-local-path/go.mod",
			replace: true,
			want:    GoModReplacedWithLocalPath,
		},
		{
			name:    "replaced with local path and version",
			file:    "testdata/replaced-with-local-path-and-version/go.mod",
			replace: true,
			want:    GoModReplacedWithLocalPathAndVersion,
		},
		{
			name:    "replaced with local path and version, mismatch",
			file:    "testdata/replaced-with-local-path-and-version-mismatch/go.mod",
			replace: true,
			want:    GoModReplacedWithLocalPathAndVersionMismatch,
		},
		{
			name:    "go 1.16",
			file:    "testdata/go116/go.mod",
			replace: true,
			want:    GoMod116,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, _, err := NewParser(tt.replace).Parse(f)
			require.NoError(t, err)

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(tt.want))

			assert.Equal(t, tt.want, got)
		})
	}
}

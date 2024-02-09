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
		name    string
		file    string
		replace bool
		want    []types.Library
	}{
		{
			name:    "normal",
			file:    "testdata/normal/go.mod",
			replace: true,
			want:    GoModNormal,
		},
		{
			name:    "without go version",
			file:    "testdata/no-go-version/go.mod",
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

func TestModuleID(t *testing.T) {
	type args struct {
		name    string
		version string
	}
	tests := []struct {
		name string
		args args
		want string
	}{
		{
			name: "normal",
			args: args{
				name:    "github.com/aquasecurity/trivy",
				version: "0.38.0",
			},
			want: "github.com/aquasecurity/trivy@v0.38.0",
		},
		{
			name: "pseudo version",
			args: args{
				name:    "github.com/aquasecurity/go-dep-parser",
				version: "0.0.0-20230130190635-5e31092b0621",
			},
			want: "github.com/aquasecurity/go-dep-parser@v0.0.0-20230130190635-5e31092b0621",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equalf(t, tt.want, ModuleID(tt.args.name, tt.args.version), "ModuleID(%v, %v)", tt.args.name, tt.args.version)
		})
	}
}

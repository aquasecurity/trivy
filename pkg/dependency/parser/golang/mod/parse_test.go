package mod

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/mod/modfile"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name             string
		file             string
		replace          bool
		useMinVersion    bool
		wantPkgs         []ftypes.Package
		wantDeps         []ftypes.Dependency
		wantSkipIndirect bool
	}{
		{
			name:             "normal with stdlib",
			file:             "testdata/normal/go.mod",
			replace:          true,
			useMinVersion:    true,
			wantPkgs:         GoModNormal,
			wantDeps:         GoModNormalDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "normal",
			file:             "testdata/normal/go.mod",
			replace:          true,
			wantPkgs:         GoModNormalWithoutStdlib,
			wantDeps:         GoModNormalWithoutStdlibDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "without go version",
			file:             "testdata/no-go-version/gomod",
			replace:          true,
			wantPkgs:         GoModNoGoVersion,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: true,
		},
		{
			name:             "replace",
			file:             "testdata/replaced/go.mod",
			replace:          true,
			wantPkgs:         GoModReplaced,
			wantDeps:         GoModReplacedDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "no replace",
			file:             "testdata/replaced/go.mod",
			replace:          false,
			wantPkgs:         GoModUnreplaced,
			wantDeps:         GoModUnreplacedDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "replace with version",
			file:             "testdata/replaced-with-version/go.mod",
			replace:          true,
			wantPkgs:         GoModReplacedWithVersion,
			wantDeps:         GoModReplacedWithVersionDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "replaced with version mismatch",
			file:             "testdata/replaced-with-version-mismatch/go.mod",
			replace:          true,
			wantPkgs:         GoModReplacedWithVersionMismatch,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "replaced with local path",
			file:             "testdata/replaced-with-local-path/go.mod",
			replace:          true,
			wantPkgs:         GoModReplacedWithLocalPath,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "replaced with local path and version",
			file:             "testdata/replaced-with-local-path-and-version/go.mod",
			replace:          true,
			wantPkgs:         GoModReplacedWithLocalPathAndVersion,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "replaced with local path and version, mismatch",
			file:             "testdata/replaced-with-local-path-and-version-mismatch/go.mod",
			replace:          true,
			wantPkgs:         GoModReplacedWithLocalPathAndVersionMismatch,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: false,
		},
		{
			name:             "go 1.16",
			file:             "testdata/go116/go.mod",
			replace:          true,
			wantPkgs:         GoMod116,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: true,
		},
		{
			name:             "go 1.17rc1",
			file:             "testdata/go117rc1/gomod",
			replace:          true,
			wantPkgs:         GoMod116,
			wantDeps:         defaultGoDepParserDeps,
			wantSkipIndirect: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			gotPkgs, gotDeps, gotSkipIndirect, err := NewParser(tt.replace, tt.useMinVersion).Parse(t.Context(), f)
			require.NoError(t, err)

			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
			assert.Equal(t, tt.wantSkipIndirect, gotSkipIndirect)
		})
	}
}

func TestToolchainVersion(t *testing.T) {
	tests := []struct {
		name    string
		modFile modfile.File
		want    string
	}{
		{
			name: "version from toolchain line",
			modFile: modfile.File{
				Toolchain: &modfile.Toolchain{
					Name: "1.21.1",
				},
			},
			want: "1.21.1",
		},
		{
			name: "version from toolchain line with suffix",
			modFile: modfile.File{
				Toolchain: &modfile.Toolchain{
					Name: "1.21.1-custom",
				},
			},
			want: "1.21.1",
		},
		{
			name: "'1.18rc1' from go line",
			modFile: modfile.File{
				Go: &modfile.Go{
					Version: "1.18rc1",
				},
			},
			want: "",
		},
		{
			name: "'1.18.1' from go line",
			modFile: modfile.File{
				Go: &modfile.Go{
					Version: "1.18.1",
				},
			},
			want: "",
		},
		{
			name: "'1.20' from go line",
			modFile: modfile.File{
				Go: &modfile.Go{
					Version: "1.20",
				},
			},
			want: "",
		},
		{
			name: "'1.21' from go line",
			modFile: modfile.File{
				Go: &modfile.Go{
					Version: "1.21",
				},
			},
			want: "1.21.0",
		},
		{
			name: "'1.21rc1' from go line",
			modFile: modfile.File{
				Go: &modfile.Go{
					Version: "1.21rc1",
				},
			},
			want: "1.21rc1",
		},
		{
			name: "'1.21.2' from go line",
			modFile: modfile.File{
				Go: &modfile.Go{
					Version: "1.21.2",
				},
			},
			want: "1.21.2",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			require.Equal(t, tt.want, toolchainVersion(tt.modFile.Toolchain, tt.modFile.Go))
		})
	}
}

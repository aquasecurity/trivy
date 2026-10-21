package mod

import (
	"os"
	"strings"
	"testing"

	"github.com/samber/lo"
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

func TestParseEchoVersions(t *testing.T) {
	const goMod = `module example.com/app

go 1.22.0

require (
	golang.org/x/net v0.55.0+echo.1
	example.com/replaced v1.3.4+echo.1
	example.com/mismatch v1.4.5+echo.1
	example.com/ordinary v1.5.6+build.1
	example.com/v2module/v2 v2.0.0+echo.1
)

replace (
	example.com/replaced v1.3.4+echo.1 => example.com/replacement v1.3.4+echo.2
	example.com/mismatch v1.4.5+echo.2 => example.com/not-used v1.4.5+echo.3
)
`

	gotPkgs, gotDeps, gotSkipIndirect, err := NewParser(true, false).Parse(t.Context(), strings.NewReader(goMod))
	require.NoError(t, err)
	require.False(t, gotSkipIndirect)

	pkgs := make(map[string]ftypes.Package, len(gotPkgs))
	for _, pkg := range gotPkgs {
		pkgs[pkg.Name] = pkg
	}

	require.Len(t, pkgs, 6)
	require.Equal(t, "v0.55.0+echo.1", pkgs["golang.org/x/net"].Version)
	require.Equal(t, "golang.org/x/net@v0.55.0+echo.1", pkgs["golang.org/x/net"].ID)
	require.Equal(t, "v1.3.4+echo.2", pkgs["example.com/replacement"].Version)
	require.Equal(t, "example.com/replacement@v1.3.4+echo.2", pkgs["example.com/replacement"].ID)
	require.Equal(t, "v1.4.5+echo.1", pkgs["example.com/mismatch"].Version)
	require.Equal(t, "v1.5.6", pkgs["example.com/ordinary"].Version)
	require.Equal(t, "v2.0.0+echo.1", pkgs["example.com/v2module/v2"].Version)
	require.NotContains(t, pkgs, "example.com/replaced")
	require.NotContains(t, pkgs, "example.com/not-used")

	require.Equal(t, []ftypes.Dependency{
		{
			ID: "example.com/app",
			DependsOn: []string{
				"example.com/mismatch@v1.4.5+echo.1",
				"example.com/ordinary@v1.5.6",
				"example.com/replacement@v1.3.4+echo.2",
				"example.com/v2module/v2@v2.0.0+echo.1",
				"golang.org/x/net@v0.55.0+echo.1",
			},
		},
	}, gotDeps)
}

func TestCanonicalizeVersion(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
		wantErr bool
	}{
		{
			name:    "Echo version",
			version: "v0.55.0+echo.1",
			want:    "v0.55.0+echo.1",
		},
		{
			name:    "Echo prerelease version",
			version: "v1.2.3-rc.1+echo.2",
			want:    "v1.2.3-rc.1+echo.2",
		},
		{
			name:    "zero Echo revision",
			version: "v1.2.3+echo.0",
			want:    "v1.2.3+echo.0",
		},
		{
			name:    "zero-padded Echo revision",
			version: "v1.2.3+echo.01",
			want:    "v1.2.3",
		},
		{
			name:    "non-Echo build metadata",
			version: "v1.2.3+build.1",
			want:    "v1.2.3",
		},
		{
			name:    "Echo segment followed by another identifier",
			version: "v1.2.3+echo.1.extra",
			want:    "v1.2.3",
		},
		{
			name:    "non-numeric Echo revision",
			version: "v1.2.3+echo.x",
			want:    "v1.2.3",
		},
		{
			name:    "Echo-like identifier",
			version: "v1.2.3+echo.1foo",
			want:    "v1.2.3",
		},
		{
			name:    "incompatible version",
			version: "v2.0.0+incompatible",
			want:    "v2.0.0+incompatible",
		},
		{
			name:    "malformed Echo version",
			version: "not-a-version+echo.1",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := canonicalizeVersion("example.com/module", tt.version)
			if tt.wantErr {
				require.ErrorContains(t, err, "invalid version: must be of the form v1.2.3")
				return
			}
			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func TestParsePreservesRetractVersionQueries(t *testing.T) {
	tests := []struct {
		name    string
		retract string
	}{
		{
			name:    "single version query",
			retract: "master",
		},
		{
			name:    "version query interval",
			retract: "[master, release-branch]",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goMod := `module example.com/app

go 1.22.0

require golang.org/x/net v0.55.0+echo.1

retract ` + tt.retract + "\n"

			gotPkgs, _, _, err := NewParser(true, false).Parse(t.Context(), strings.NewReader(goMod))
			require.NoError(t, err)

			pkg, found := lo.Find(gotPkgs, func(pkg ftypes.Package) bool {
				return pkg.Name == "golang.org/x/net"
			})
			require.True(t, found)
			require.Equal(t, "v0.55.0+echo.1", pkg.Version)
		})
	}
}

func TestParsePreservesModulelessRetract(t *testing.T) {
	const goMod = `retract master`

	gotPkgs, gotDeps, _, err := NewParser(true, false).Parse(t.Context(), strings.NewReader(goMod))
	require.NoError(t, err)
	require.Empty(t, gotPkgs)
	require.Empty(t, gotDeps)
}

func TestParseRejectsInvalidDependencyVersions(t *testing.T) {
	tests := []struct {
		name  string
		goMod string
	}{
		{
			name: "require",
			goMod: `module example.com/app

go 1.22.0

require example.com/module not-a-version
`,
		},
		{
			name: "replacement",
			goMod: `module example.com/app

go 1.22.0

require example.com/module v1.2.3

replace example.com/module => example.com/replacement not-a-version
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, wantErr := modfile.Parse("go.mod", []byte(tt.goMod), nil)
			require.Error(t, wantErr)

			_, _, _, gotErr := NewParser(true, false).Parse(t.Context(), strings.NewReader(tt.goMod))
			require.EqualError(t, gotErr, "go.mod parse error: "+wantErr.Error())
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

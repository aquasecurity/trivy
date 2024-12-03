package pnpm

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []ftypes.Package
		wantDeps []ftypes.Dependency
	}{
		{
			name:     "normal",
			file:     "testdata/pnpm-lock_normal.yaml",
			want:     pnpmNormal,
			wantDeps: pnpmNormalDeps,
		},
		{
			name:     "with dev deps",
			file:     "testdata/pnpm-lock_with_dev.yaml",
			want:     pnpmWithDev,
			wantDeps: pnpmWithDevDeps,
		},
		{
			name:     "many",
			file:     "testdata/pnpm-lock_many.yaml",
			want:     pnpmMany,
			wantDeps: pnpmManyDeps,
		},
		{
			name:     "archives",
			file:     "testdata/pnpm-lock_archives.yaml",
			want:     pnpmArchives,
			wantDeps: pnpmArchivesDeps,
		},
		{
			name:     "v6",
			file:     "testdata/pnpm-lock_v6.yaml",
			want:     pnpmV6,
			wantDeps: pnpmV6Deps,
		},
		{
			name:     "v6 with dev deps",
			file:     "testdata/pnpm-lock_v6_with_dev.yaml",
			want:     pnpmV6WithDev,
			wantDeps: pnpmV6WithDevDeps,
		},
		{
			name:     "v9",
			file:     "testdata/pnpm-lock_v9.yaml",
			want:     pnpmV9,
			wantDeps: pnpmV9Deps,
		},
		{
			name:     "v9 with cyclic dependencies import",
			file:     "testdata/pnpm-lock_v9_cyclic_import.yaml",
			want:     pnpmV9CyclicImport,
			wantDeps: pnpmV9CyclicImportDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, deps, err := NewParser().Parse(f)
			require.NoError(t, err)

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(tt.want))
			require.Equal(t, tt.want, got)

			if tt.wantDeps != nil {
				sort.Sort(ftypes.Dependencies(deps))
				sort.Sort(ftypes.Dependencies(tt.wantDeps))
				for _, dep := range deps {
					sort.Strings(dep.DependsOn)
				}
				for _, dep := range tt.wantDeps {
					sort.Strings(dep.DependsOn)
				}
				require.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}

func Test_parseDepPath(t *testing.T) {
	tests := []struct {
		name        string
		lockFileVer float64
		pkg         string
		wantName    string
		wantVersion string
		wantRef     string
	}{
		{
			name:        "v5 - relative path",
			lockFileVer: 5.0,
			pkg:         "/lodash/4.17.10",
			wantName:    "lodash",
			wantVersion: "4.17.10",
		},
		{
			name:        "v5 - registry",
			lockFileVer: 5.0,
			pkg:         "registry.npmjs.org/lodash/4.17.10",
			wantName:    "lodash",
			wantVersion: "4.17.10",
		},
		{
			name:        "v5 - non-default registry",
			lockFileVer: 5.0,
			pkg:         "private.npmjs.org/lodash/4.17.10",
			wantName:    "lodash",
			wantVersion: "4.17.10",
			wantRef:     "private.npmjs.org/lodash/4.17.10",
		},
		{
			name:        "v5 - relative path with slash",
			lockFileVer: 5.0,
			pkg:         "/@babel/generator/7.21.9",
			wantName:    "@babel/generator",
			wantVersion: "7.21.9",
		},
		{
			name:        "v5 - registry path with slash",
			lockFileVer: 5.0,
			pkg:         "registry.npmjs.org/@babel/generator/7.21.9",
			wantName:    "@babel/generator",
			wantVersion: "7.21.9",
		},
		{
			name:        "v5 - relative path with slash and peer deps",
			lockFileVer: 5.0,
			pkg:         "/@babel/helper-compilation-targets/7.21.5_@babel+core@7.21.8",
			wantName:    "@babel/helper-compilation-targets",
			wantVersion: "7.21.5",
		},
		{
			name:        "v5 - relative path with underline and peer deps",
			lockFileVer: 5.0,
			pkg:         "/lodash._baseclone/4.5.7_@babel+core@7.21.8",
			wantName:    "lodash._baseclone",
			wantVersion: "4.5.7",
		},
		{
			name:        "v5 - registry with slash and peer deps",
			lockFileVer: 5.0,
			pkg:         "registry.npmjs.org/@babel/helper-compilation-targets/7.21.5_@babel+core@7.21.8",
			wantName:    "@babel/helper-compilation-targets",
			wantVersion: "7.21.5",
		},
		{
			name:        "v6 - relative path",
			lockFileVer: 6.0,
			pkg:         "/update-browserslist-db@1.0.11",
			wantName:    "update-browserslist-db",
			wantVersion: "1.0.11",
		},
		{
			name:        "v6 - registry",
			lockFileVer: 6.0,
			pkg:         "registry.npmjs.org/lodash@4.17.10",
			wantName:    "lodash",
			wantVersion: "4.17.10",
		},
		{
			name:        "v6 - non-default registry",
			lockFileVer: 6.0,
			pkg:         "private.npmjs.org/lodash@4.17.10",
			wantName:    "lodash",
			wantVersion: "4.17.10",
			wantRef:     "private.npmjs.org/lodash@4.17.10",
		},
		{
			name:        "v6 - relative path with slash",
			lockFileVer: 6.0,
			pkg:         "/@babel/helper-annotate-as-pure@7.18.6",
			wantName:    "@babel/helper-annotate-as-pure",
			wantVersion: "7.18.6",
		},
		{
			name:        "v6 - registry with slash",
			lockFileVer: 6.0,
			pkg:         "registry.npmjs.org/@babel/helper-annotate-as-pure@7.18.6",
			wantName:    "@babel/helper-annotate-as-pure",
			wantVersion: "7.18.6",
		},
		{
			name:        "v6 - relative path with slash and peer deps",
			lockFileVer: 6.0,
			pkg:         "/@babel/helper-compilation-targets@7.21.5(@babel/core@7.20.7)",
			wantName:    "@babel/helper-compilation-targets",
			wantVersion: "7.21.5",
		},
		{
			name:        "v6 - registry with slash and peer deps",
			lockFileVer: 6.0,
			pkg:         "registry.npmjs.org/@babel/helper-compilation-targets@7.21.5(@babel/core@7.20.7)",
			wantName:    "@babel/helper-compilation-targets",
			wantVersion: "7.21.5",
		},
		{
			name:        "v9 - scope and peer deps",
			lockFileVer: 9.0,
			pkg:         "@babel/helper-compilation-targets@7.21.5(@babel/core@7.20.7)",
			wantName:    "@babel/helper-compilation-targets",
			wantVersion: "7.21.5",
		},
		{
			name:        "v9 - filePath as version",
			lockFileVer: 9.0,
			pkg:         "lodash@file:foo/bar/lodash.tgz",
			wantName:    "lodash",
			wantVersion: "file:foo/bar/lodash.tgz",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			gotName, gotVersion, gotRef := p.parseDepPath(tt.pkg, tt.lockFileVer)
			require.Equal(t, tt.wantName, gotName)
			require.Equal(t, tt.wantVersion, gotVersion)
			require.Equal(t, tt.wantRef, gotRef)
		})

	}
}

func Test_parseVersion(t *testing.T) {
	tests := []struct {
		name    string
		ver     string
		lockVer float64
		wantVer string
	}{
		{
			name:    "happy path",
			ver:     "0.0.1",
			lockVer: 5.0,
			wantVer: "0.0.1",
		},
		{
			name:    "v6 version is file",
			ver:     "file:foo/bar/lodash.tgz",
			lockVer: 6.0,
			wantVer: "",
		},
		{
			name:    "v9 version is file",
			ver:     "file:foo/bar/lodash.tgz",
			lockVer: 9.0,
			wantVer: "",
		},
		{
			name:    "v6 version is url",
			ver:     "https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5",
			lockVer: 6.0,
			wantVer: "",
		},
		{
			name:    "v9 version is url",
			ver:     "https://codeload.github.com/zkochan/is-negative/tar.gz/2fa0531ab04e300a24ef4fd7fb3a280eccb7ccc5",
			lockVer: 9.0,
			wantVer: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := NewParser()
			gotVer := p.parseVersion("depPath", tt.ver, tt.lockVer)
			require.Equal(t, tt.wantVer, gotVer)
		})

	}
}

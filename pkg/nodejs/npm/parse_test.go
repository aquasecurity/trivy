package npm

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name     string
		file     string // Test input file
		want     []types.Library
		wantDeps []types.Dependency
	}{
		{
			name:     "normal",
			file:     "testdata/package-lock_normal.json",
			want:     npmNormal,
			wantDeps: npmNormalDeps,
		},
		{
			name:     "react",
			file:     "testdata/package-lock_react.json",
			want:     npmReact,
			wantDeps: npmReactDeps,
		},
		{
			name:     "with devDependencies",
			file:     "testdata/package-lock_with_dev.json",
			want:     npmWithDev,
			wantDeps: npmWithDevDeps,
		},
		{
			name:     "many packages",
			file:     "testdata/package-lock_many.json",
			want:     npmMany,
			wantDeps: npmManyDeps,
		},
		{
			name:     "nested packages",
			file:     "testdata/package-lock_nested.json",
			want:     npmNested,
			wantDeps: npmNestedDeps,
		},
		{
			name:     "deep nested packages",
			file:     "testdata/package-lock_deep-nested.json",
			want:     npmDeepNested,
			wantDeps: npmDeepNestedDeps,
		},
		{
			name:     "direct libraries",
			file:     "testdata/package-lock_with_packages.json",
			want:     npmWithPkgs,
			wantDeps: npmWithPkgsDeps,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, deps, err := NewParser().Parse(f)
			require.NoError(t, err)

			sortLibs(got)
			sortLibs(tt.want)

			assert.Equal(t, tt.want, got)
			if tt.wantDeps != nil {
				sortDeps(deps)
				sortDeps(tt.wantDeps)
				assert.Equal(t, tt.wantDeps, deps)
			}
		})
	}
}

func sortDeps(deps []types.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return strings.Compare(deps[i].ID, deps[j].ID) < 0
	})

	for i := range deps {
		sort.Strings(deps[i].DependsOn)
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
	for _, lib := range libs {
		sortLocations(lib.Locations)
	}
}

func sortLocations(locs []types.Location) {
	sort.Slice(locs, func(i, j int) bool {
		return locs[i].StartLine < locs[j].StartLine
	})
}

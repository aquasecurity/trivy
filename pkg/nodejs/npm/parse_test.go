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
			name:     "lock version v1",
			file:     "testdata/package-lock_v1.json",
			want:     npmV1Libs,
			wantDeps: npmDeps,
		},
		{
			name:     "lock version v2",
			file:     "testdata/package-lock_v2.json",
			want:     npmV2Libs,
			wantDeps: npmDeps,
		},
		{
			name:     "lock version v3",
			file:     "testdata/package-lock_v3.json",
			want:     npmV2Libs,
			wantDeps: npmDeps,
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
	for _, lib := range libs {
		sortLocations(lib.Locations)
	}
	sort.Slice(libs, func(i, j int) bool {
		return strings.Compare(libs[i].ID, libs[j].ID) < 0
	})
}

func sortLocations(locs []types.Location) {
	sort.Slice(locs, func(i, j int) bool {
		return locs[i].StartLine < locs[j].StartLine
	})
}

package lock

import (
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		want     []types.Library
		wantDeps []types.Dependency
	}{
		{
			file:     "testdata/packages_lock_simple.json",
			want:     nuGetSimple,
			wantDeps: nuGetSimpleDeps,
		},
		{
			file:     "testdata/packages_lock_subdependencies.json",
			want:     nuGetSubDependencies,
			wantDeps: nuGetSubDependenciesDeps,
		},
		{
			file:     "testdata/packages_lock_multi.json",
			want:     nuGetMultiTarget,
			wantDeps: nuGetMultiTargetDeps,
		},
		{
			file:     "testdata/packages_lock_legacy.json",
			want:     nuGetLegacy,
			wantDeps: nuGetLegacyDeps,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			got, deps, err := NewParser().Parse(f)
			require.NoError(t, err)

			sort.Slice(got, func(i, j int) bool {
				ret := strings.Compare(got[i].Name, got[j].Name)
				if ret == 0 {
					return got[i].Version < got[j].Version
				}
				return ret < 0
			})

			sort.Slice(v.want, func(i, j int) bool {
				ret := strings.Compare(v.want[i].Name, v.want[j].Name)
				if ret == 0 {
					return v.want[i].Version < v.want[j].Version
				}
				return ret < 0
			})

			assert.Equal(t, v.want, got)

			if v.wantDeps != nil {
				sortDeps(deps)
				sortDeps(v.wantDeps)
				assert.Equal(t, v.wantDeps, deps)
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

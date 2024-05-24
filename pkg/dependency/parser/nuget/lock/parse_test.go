package lock

import (
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		want     []ftypes.Package
		wantDeps []ftypes.Dependency
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

			sort.Sort(ftypes.Packages(got))
			sort.Sort(ftypes.Packages(v.want))

			assert.Equal(t, v.want, got)

			if v.wantDeps != nil {
				sortDeps(deps)
				sortDeps(v.wantDeps)
				assert.Equal(t, v.wantDeps, deps)
			}
		})
	}
}

func sortDeps(deps []ftypes.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return deps[i].ID < deps[j].ID
	})

	for i := range deps {
		sort.Strings(deps[i].DependsOn)
	}
}

package cargo

import (
	"fmt"
	"os"
	"path"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

var (
	cargoNormalLibs = []types.Library{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Locations: []types.Location{{StartLine: 8, EndLine: 13}}},
		{ID: "libc@0.2.54", Name: "libc", Version: "0.2.54", Locations: []types.Location{{StartLine: 3, EndLine: 6}}},
		{ID: "typemap@0.3.3", Name: "typemap", Version: "0.3.3", Locations: []types.Location{{StartLine: 20, EndLine: 26}}},
		{ID: "url@1.7.2", Name: "url", Version: "1.7.2", Locations: []types.Location{{StartLine: 43, EndLine: 51}}},
		{ID: "unsafe-any@0.4.2", Name: "unsafe-any", Version: "0.4.2", Locations: []types.Location{{StartLine: 15, EndLine: 18}}},
		{ID: "matches@0.1.8", Name: "matches", Version: "0.1.8", Locations: []types.Location{{StartLine: 33, EndLine: 36}}},
		{ID: "idna@0.1.5", Name: "idna", Version: "0.1.5", Locations: []types.Location{{StartLine: 28, EndLine: 31}}},
		{ID: "percent-encoding@1.0.1", Name: "percent-encoding", Version: "1.0.1", Locations: []types.Location{{StartLine: 38, EndLine: 41}}},
	}
	cargoNormalDeps = []types.Dependency{
		{
			ID:        "normal@0.1.0",
			DependsOn: []string{"libc@0.2.54"}},
		{
			ID:        "typemap@0.3.3",
			DependsOn: []string{"unsafe-any@0.4.2"},
		},
		{
			ID:        "url@1.7.2",
			DependsOn: []string{"idna@0.1.5", "matches@0.1.8", "percent-encoding@1.0.1"},
		},
	}
	cargoMixedLibs = []types.Library{
		{ID: "normal@0.1.0", Name: "normal", Version: "0.1.0", Locations: []types.Location{{StartLine: 17, EndLine: 22}}},
		{ID: "libc@0.2.54", Name: "libc", Version: "0.2.54", Locations: []types.Location{{StartLine: 3, EndLine: 6}}},
		{ID: "typemap@0.3.3", Name: "typemap", Version: "0.3.3", Locations: []types.Location{{StartLine: 55, EndLine: 61}}},
		{ID: "url@1.7.2", Name: "url", Version: "1.7.2", Locations: []types.Location{{StartLine: 26, EndLine: 34}}},
		{ID: "unsafe-any@0.4.2", Name: "unsafe-any", Version: "0.4.2", Locations: []types.Location{{StartLine: 9, EndLine: 12}}},
		{ID: "matches@0.1.8", Name: "matches", Version: "0.1.8", Locations: []types.Location{{StartLine: 41, EndLine: 44}}},
		{ID: "idna@0.1.5", Name: "idna", Version: "0.1.5", Locations: []types.Location{{StartLine: 36, EndLine: 39}}},
		{ID: "percent-encoding@1.0.1", Name: "percent-encoding", Version: "1.0.1", Locations: []types.Location{{StartLine: 46, EndLine: 49}}},
	}
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		wantLibs []types.Library
		wantDeps []types.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			file:     "testdata/cargo_normal.lock",
			wantLibs: cargoNormalLibs,
			wantDeps: cargoNormalDeps,
			wantErr:  assert.NoError,
		},
		{
			file:     "testdata/cargo_mixed.lock",
			wantLibs: cargoMixedLibs,
			wantDeps: cargoNormalDeps,
			wantErr:  assert.NoError,
		},
		{
			file:    "testdata/cargo_invalid.lock",
			wantErr: assert.Error,
		},
	}

	for _, v := range vectors {
		t.Run(path.Base(v.file), func(t *testing.T) {
			f, err := os.Open(v.file)
			require.NoError(t, err)

			libs, deps, err := NewParser().Parse(f)

			if !v.wantErr(t, err, fmt.Sprintf("Parse(%v)", v.file)) {
				return
			}

			if err != nil {
				return
			}

			sortLibs(libs)
			sortLibs(v.wantLibs)

			sortDeps(deps)
			sortDeps(v.wantDeps)

			assert.Equalf(t, v.wantLibs, libs, "Parse libraries(%v)", v.file)
			assert.Equalf(t, v.wantDeps, deps, "Parse dependencies(%v)", v.file)
		})
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		return strings.Compare(libs[i].ID, libs[j].ID) < 0
	})
}

func sortDeps(deps []types.Dependency) {
	sort.Slice(deps, func(i, j int) bool {
		return strings.Compare(deps[i].ID, deps[j].ID) < 0
	})
}

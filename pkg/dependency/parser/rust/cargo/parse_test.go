package cargo

import (
	"fmt"
	"os"
	"path"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	cargoNormalPkgs = []ftypes.Package{
		{
			ID:      "normal@0.1.0",
			Name:    "normal",
			Version: "0.1.0",
			Locations: []ftypes.Location{
				{
					StartLine: 8,
					EndLine:   13,
				},
			},
		},
		{
			ID:      "libc@0.2.54",
			Name:    "libc",
			Version: "0.2.54",
			Locations: []ftypes.Location{
				{
					StartLine: 3,
					EndLine:   6,
				},
			},
		},
		{
			ID:      "typemap@0.3.3",
			Name:    "typemap",
			Version: "0.3.3",
			Locations: []ftypes.Location{
				{
					StartLine: 20,
					EndLine:   26,
				},
			},
		},
		{
			ID:      "url@1.7.2",
			Name:    "url",
			Version: "1.7.2",
			Locations: []ftypes.Location{
				{
					StartLine: 43,
					EndLine:   51,
				},
			},
		},
		{
			ID:      "unsafe-any@0.4.2",
			Name:    "unsafe-any",
			Version: "0.4.2",
			Locations: []ftypes.Location{
				{
					StartLine: 15,
					EndLine:   18,
				},
			},
		},
		{
			ID:      "matches@0.1.8",
			Name:    "matches",
			Version: "0.1.8",
			Locations: []ftypes.Location{
				{
					StartLine: 33,
					EndLine:   36,
				},
			},
		},
		{
			ID:      "idna@0.1.5",
			Name:    "idna",
			Version: "0.1.5",
			Locations: []ftypes.Location{
				{
					StartLine: 28,
					EndLine:   31,
				},
			},
		},
		{
			ID:      "percent-encoding@1.0.1",
			Name:    "percent-encoding",
			Version: "1.0.1",
			Locations: []ftypes.Location{
				{
					StartLine: 38,
					EndLine:   41,
				},
			},
		},
	}
	cargoNormalDeps = []ftypes.Dependency{
		{
			ID:        "normal@0.1.0",
			DependsOn: []string{"libc@0.2.54"},
		},
		{
			ID:        "typemap@0.3.3",
			DependsOn: []string{"unsafe-any@0.4.2"},
		},
		{
			ID: "url@1.7.2",
			DependsOn: []string{
				"idna@0.1.5",
				"matches@0.1.8",
				"percent-encoding@1.0.1",
			},
		},
	}
	cargoMixedPkgs = []ftypes.Package{
		{
			ID:      "normal@0.1.0",
			Name:    "normal",
			Version: "0.1.0",
			Locations: []ftypes.Location{
				{
					StartLine: 17,
					EndLine:   22,
				},
			},
		},
		{
			ID:      "libc@0.2.54",
			Name:    "libc",
			Version: "0.2.54",
			Locations: []ftypes.Location{
				{
					StartLine: 3,
					EndLine:   6,
				},
			},
		},
		{
			ID:      "typemap@0.3.3",
			Name:    "typemap",
			Version: "0.3.3",
			Locations: []ftypes.Location{
				{
					StartLine: 55,
					EndLine:   61,
				},
			},
		},
		{
			ID:      "url@1.7.2",
			Name:    "url",
			Version: "1.7.2",
			Locations: []ftypes.Location{
				{
					StartLine: 26,
					EndLine:   34,
				},
			},
		},
		{
			ID:      "unsafe-any@0.4.2",
			Name:    "unsafe-any",
			Version: "0.4.2",
			Locations: []ftypes.Location{
				{
					StartLine: 9,
					EndLine:   12,
				},
			},
		},
		{
			ID:      "matches@0.1.8",
			Name:    "matches",
			Version: "0.1.8",
			Locations: []ftypes.Location{
				{
					StartLine: 41,
					EndLine:   44,
				},
			},
		},
		{
			ID:      "idna@0.1.5",
			Name:    "idna",
			Version: "0.1.5",
			Locations: []ftypes.Location{
				{
					StartLine: 36,
					EndLine:   39,
				},
			},
		},
		{
			ID:      "percent-encoding@1.0.1",
			Name:    "percent-encoding",
			Version: "1.0.1",
			Locations: []ftypes.Location{
				{
					StartLine: 46,
					EndLine:   49,
				},
			},
		},
	}
	cargoV3Pkgs = []ftypes.Package{
		{
			ID:      "aho-corasick@0.7.20",
			Name:    "aho-corasick",
			Version: "0.7.20",
			Locations: []ftypes.Location{
				{
					StartLine: 5,
					EndLine:   12,
				},
			},
		},
		{
			ID:      "app@0.1.0",
			Name:    "app",
			Version: "0.1.0",
			Locations: []ftypes.Location{
				{
					StartLine: 14,
					EndLine:   21,
				},
			},
		},
		{
			ID:      "libc@0.2.140",
			Name:    "libc",
			Version: "0.2.140",
			Locations: []ftypes.Location{
				{
					StartLine: 23,
					EndLine:   27,
				},
			},
		},
		{
			ID:      "memchr@1.0.2",
			Name:    "memchr",
			Version: "1.0.2",
			Locations: []ftypes.Location{
				{
					StartLine: 29,
					EndLine:   36,
				},
			},
		},
		{
			ID:      "memchr@2.5.0",
			Name:    "memchr",
			Version: "2.5.0",
			Locations: []ftypes.Location{
				{
					StartLine: 38,
					EndLine:   42,
				},
			},
		},
		{
			ID:      "regex@1.7.3",
			Name:    "regex",
			Version: "1.7.3",
			Locations: []ftypes.Location{
				{
					StartLine: 44,
					EndLine:   53,
				},
			},
		},
		{
			ID:      "regex-syntax@0.5.6",
			Name:    "regex-syntax",
			Version: "0.5.6",
			Locations: []ftypes.Location{
				{
					StartLine: 55,
					EndLine:   62,
				},
			},
		},
		{
			ID:      "regex-syntax@0.6.29",
			Name:    "regex-syntax",
			Version: "0.6.29",
			Locations: []ftypes.Location{
				{
					StartLine: 64,
					EndLine:   68,
				},
			},
		},
		{
			ID:      "ucd-util@0.1.10",
			Name:    "ucd-util",
			Version: "0.1.10",
			Locations: []ftypes.Location{
				{
					StartLine: 70,
					EndLine:   74,
				},
			},
		},
	}

	cargoV3Deps = []ftypes.Dependency{
		{
			ID:        "aho-corasick@0.7.20",
			DependsOn: []string{"memchr@2.5.0"},
		},
		{
			ID: "app@0.1.0",
			DependsOn: []string{
				"memchr@1.0.2",
				"regex-syntax@0.5.6",
				"regex@1.7.3",
			},
		},
		{
			ID:        "memchr@1.0.2",
			DependsOn: []string{"libc@0.2.140"},
		},
		{
			ID: "regex@1.7.3",
			DependsOn: []string{
				"aho-corasick@0.7.20",
				"memchr@2.5.0",
				"regex-syntax@0.6.29",
			},
		},
		{
			ID:        "regex-syntax@0.5.6",
			DependsOn: []string{"ucd-util@0.1.10"},
		},
	}
)

func TestParse(t *testing.T) {
	vectors := []struct {
		file     string // Test input file
		wantPkgs []ftypes.Package
		wantDeps []ftypes.Dependency
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			file:     "testdata/cargo_normal.lock",
			wantPkgs: cargoNormalPkgs,
			wantDeps: cargoNormalDeps,
			wantErr:  assert.NoError,
		},
		{
			file:     "testdata/cargo_mixed.lock",
			wantPkgs: cargoMixedPkgs,
			wantDeps: cargoNormalDeps,
			wantErr:  assert.NoError,
		},
		{
			file:     "testdata/cargo_v3.lock",
			wantPkgs: cargoV3Pkgs,
			wantDeps: cargoV3Deps,
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

			gotPkgs, gotDeps, err := NewParser().Parse(f)

			if !v.wantErr(t, err, fmt.Sprintf("Parse(%v)", v.file)) {
				return
			}

			if err != nil {
				return
			}

			sort.Sort(ftypes.Packages(v.wantPkgs))
			sort.Sort(ftypes.Dependencies(v.wantDeps))
			assert.Equalf(t, v.wantPkgs, gotPkgs, "Parse libraries(%v)", v.file)
			assert.Equalf(t, v.wantDeps, gotDeps, "Parse dependencies(%v)", v.file)
		})
	}
}

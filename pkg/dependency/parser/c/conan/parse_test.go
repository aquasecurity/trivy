package conan_test

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/c/conan"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string // Test input file
		wantPkgs  []ftypes.Package
		wantDeps  []ftypes.Dependency
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy_v1_case1.lock",
			wantPkgs: []ftypes.Package{
				{
					ID:           "pkga/0.0.1",
					Name:         "pkga",
					Version:      "0.0.1",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 13,
							EndLine:   22,
						},
					},
				},
				{
					ID:           "pkgc/0.1.1",
					Name:         "pkgc",
					Version:      "0.1.1",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 30,
							EndLine:   35,
						},
					},
				},
				{
					ID:           "pkgb/system",
					Name:         "pkgb",
					Version:      "system",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 23,
							EndLine:   29,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "pkga/0.0.1",
					DependsOn: []string{
						"pkgb/system",
					},
				},
			},
		},
		{
			name:      "happy path. lock file with revisions support",
			inputFile: "testdata/happy_v1_case2.lock",
			wantPkgs: []ftypes.Package{
				{
					ID:           "openssl/3.0.3",
					Name:         "openssl",
					Version:      "3.0.3",
					Relationship: ftypes.RelationshipDirect,
					Locations: []ftypes.Location{
						{
							StartLine: 12,
							EndLine:   22,
						},
					},
				},
				{
					ID:           "zlib/1.2.12",
					Name:         "zlib",
					Version:      "1.2.12",
					Relationship: ftypes.RelationshipIndirect,
					Locations: []ftypes.Location{
						{
							StartLine: 23,
							EndLine:   30,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{
				{
					ID: "openssl/3.0.3",
					DependsOn: []string{
						"zlib/1.2.12",
					},
				},
			},
		},
		{
			name:      "happy path conan v2",
			inputFile: "testdata/happy_v2.lock",
			wantPkgs: []ftypes.Package{
				{
					ID:      "matrix/1.3",
					Name:    "matrix",
					Version: "1.3",
					Locations: []ftypes.Location{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					ID:      "sound32/1.0",
					Name:    "sound32",
					Version: "1.0",
					Locations: []ftypes.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
			},
			wantDeps: []ftypes.Dependency{},
		},
		{
			name:      "happy path. lock file without dependencies",
			inputFile: "testdata/empty_v1.lock",
		},
		{
			name:      "sad path. wrong ref format",
			inputFile: "testdata/sad_v1.lock",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			gotPkgs, gotDeps, err := conan.NewParser().Parse(f)
			require.NoError(t, err)

			sort.Sort(ftypes.Packages(gotPkgs))

			assert.Equal(t, tt.wantPkgs, gotPkgs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}

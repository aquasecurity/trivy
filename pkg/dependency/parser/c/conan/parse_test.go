package conan_test

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/c/conan"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string // Test input file
		wantLibs  []types.Library
		wantDeps  []types.Dependency
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy_v1_case1.lock",
			wantLibs: []types.Library{
				{
					ID:           "pkga/0.0.1",
					Name:         "pkga",
					Version:      "0.0.1",
					Relationship: types.RelationshipDirect,
					Locations: []types.Location{
						{
							StartLine: 13,
							EndLine:   22,
						},
					},
				},
				{
					ID:           "pkgb/system",
					Name:         "pkgb",
					Version:      "system",
					Relationship: types.RelationshipIndirect,
					Locations: []types.Location{
						{
							StartLine: 23,
							EndLine:   29,
						},
					},
				},
				{
					ID:           "pkgc/0.1.1",
					Name:         "pkgc",
					Version:      "0.1.1",
					Relationship: types.RelationshipDirect,
					Locations: []types.Location{
						{
							StartLine: 30,
							EndLine:   35,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
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
			wantLibs: []types.Library{
				{
					ID:           "openssl/3.0.3",
					Name:         "openssl",
					Version:      "3.0.3",
					Relationship: types.RelationshipDirect,
					Locations: []types.Location{
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
					Relationship: types.RelationshipIndirect,
					Locations: []types.Location{
						{
							StartLine: 23,
							EndLine:   30,
						},
					},
				},
			},
			wantDeps: []types.Dependency{
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
			wantLibs: []types.Library{
				{
					ID:      "matrix/1.3",
					Name:    "matrix",
					Version: "1.3",
					Locations: []types.Location{
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
					Locations: []types.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
			},
			wantDeps: []types.Dependency{},
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

			gotLibs, gotDeps, err := conan.NewParser().Parse(f)
			require.NoError(t, err)

			sort.Slice(gotLibs, func(i, j int) bool {
				ret := strings.Compare(gotLibs[i].Name, gotLibs[j].Name)
				if ret != 0 {
					return ret < 0
				}
				return gotLibs[i].Version < gotLibs[j].Version
			})

			assert.Equal(t, tt.wantLibs, gotLibs)
			assert.Equal(t, tt.wantDeps, gotDeps)
		})
	}
}

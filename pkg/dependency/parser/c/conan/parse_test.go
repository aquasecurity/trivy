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
			inputFile: "testdata/happy.lock",
			wantLibs: []types.Library{
				{
					ID:      "pkga/0.0.1",
					Name:    "pkga",
					Version: "0.0.1",
					Locations: []types.Location{
						{
							StartLine: 13,
							EndLine:   22,
						},
					},
				},
				{
					ID:       "pkgb/system",
					Name:     "pkgb",
					Version:  "system",
					Indirect: true,
					Locations: []types.Location{
						{
							StartLine: 23,
							EndLine:   29,
						},
					},
				},
				{
					ID:      "pkgc/0.1.1",
					Name:    "pkgc",
					Version: "0.1.1",
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
			inputFile: "testdata/happy2.lock",
			wantLibs: []types.Library{
				{
					ID:      "openssl/3.0.3",
					Name:    "openssl",
					Version: "3.0.3",
					Locations: []types.Location{
						{
							StartLine: 12,
							EndLine:   22,
						},
					},
				},
				{
					ID:       "zlib/1.2.12",
					Name:     "zlib",
					Version:  "1.2.12",
					Indirect: true,
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
			name:      "happy path. lock file without dependencies",
			inputFile: "testdata/empty.lock",
		},
		{
			name:      "sad path. wrong ref format",
			inputFile: "testdata/sad.lock",
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

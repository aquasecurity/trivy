package core_deps

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
		file    string // Test input file
		want    []types.Library
		wantErr string
	}{
		{
			file: "testdata/ExampleApp1.deps.json",
			want: []types.Library{
				{Name: "Newtonsoft.Json", Version: "13.0.1", Locations: []types.Location{{StartLine: 33, EndLine: 39}}},
			},
		},
		{
			file: "testdata/NoLibraries.deps.json",
			want: nil,
		},
		{
			file:    "testdata/InvalidJson.deps.json",
			wantErr: "failed to decode .deps.json file: EOF",
		},
	}

	for _, tt := range vectors {
		t.Run(path.Base(tt.file), func(t *testing.T) {
			f, err := os.Open(tt.file)
			require.NoError(t, err)

			got, _, err := NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)

				sort.Slice(got, func(i, j int) bool {
					ret := strings.Compare(got[i].Name, got[j].Name)
					if ret == 0 {
						return got[i].Version < got[j].Version
					}
					return ret < 0
				})

				sort.Slice(tt.want, func(i, j int) bool {
					ret := strings.Compare(tt.want[i].Name, tt.want[j].Name)
					if ret == 0 {
						return tt.want[i].Version < tt.want[j].Version
					}
					return ret < 0
				})

				assert.Equal(t, tt.want, got)
			}
		})
	}
}

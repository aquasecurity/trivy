package core_deps

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
		file    string // Test input file
		want    []ftypes.Package
		wantErr string
	}{
		{
			file: "testdata/ExampleApp1.deps.json",
			want: []ftypes.Package{
				{Name: "Newtonsoft.Json", Version: "13.0.1", Locations: []ftypes.Location{{StartLine: 33, EndLine: 39}}},
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
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
			} else {
				require.NoError(t, err)

				sort.Sort(ftypes.Packages(got))
				sort.Sort(ftypes.Packages(tt.want))

				assert.Equal(t, tt.want, got)
			}
		})
	}
}

package mix

import (
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/stretchr/testify/assert"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.mix.lock",
			want: []types.Library{
				{
					ID:        "bunt@0.2.0",
					Name:      "bunt",
					Version:   "0.2.0",
					Locations: []types.Location{{StartLine: 2, EndLine: 2}},
				},
				{
					ID:        "credo@1.6.6",
					Name:      "credo",
					Version:   "1.6.6",
					Locations: []types.Location{{StartLine: 3, EndLine: 3}},
				},
				{
					ID:        "file_system@0.2.10",
					Name:      "file_system",
					Version:   "0.2.10",
					Locations: []types.Location{{StartLine: 4, EndLine: 4}},
				},
				{
					ID:        "jason@1.3.0",
					Name:      "jason",
					Version:   "1.3.0",
					Locations: []types.Location{{StartLine: 5, EndLine: 5}},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.mix.lock",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			assert.NoError(t, err)

			libs, _, _ := parser.Parse(f)
			sortLibs(libs)
			assert.Equal(t, tt.want, libs)
		})
	}
}

func sortLibs(libs []types.Library) {
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
}

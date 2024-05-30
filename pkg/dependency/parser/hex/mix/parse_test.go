package mix

import (
	"os"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.mix.lock",
			want: []ftypes.Package{
				{
					ID:      "bunt@0.2.0",
					Name:    "bunt",
					Version: "0.2.0",
					Locations: []ftypes.Location{
						{
							StartLine: 2,
							EndLine:   2,
						},
					},
				},
				{
					ID:      "credo@1.6.6",
					Name:    "credo",
					Version: "1.6.6",
					Locations: []ftypes.Location{
						{
							StartLine: 3,
							EndLine:   3,
						},
					},
				},
				{
					ID:      "file_system@0.2.10",
					Name:    "file_system",
					Version: "0.2.10",
					Locations: []ftypes.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
				{
					ID:      "jason@1.3.0",
					Name:    "jason",
					Version: "1.3.0",
					Locations: []ftypes.Location{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
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
			require.NoError(t, err)

			pkgs, _, _ := parser.Parse(f)
			sort.Sort(ftypes.Packages(pkgs))
			assert.Equal(t, tt.want, pkgs)
		})
	}
}

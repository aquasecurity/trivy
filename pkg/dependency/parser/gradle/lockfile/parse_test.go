package lockfile

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
			inputFile: "testdata/happy.lockfile",
			want: []ftypes.Package{
				{
					ID:      "cglib:cglib-nodep:2.1.2",
					Name:    "cglib:cglib-nodep",
					Version: "2.1.2",
					Locations: []ftypes.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
				{
					ID:      "org.springframework:spring-asm:3.1.3.RELEASE",
					Name:    "org.springframework:spring-asm",
					Version: "3.1.3.RELEASE",
					Locations: []ftypes.Location{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					ID:      "org.springframework:spring-beans:5.0.5.RELEASE",
					Name:    "org.springframework:spring-beans",
					Version: "5.0.5.RELEASE",
					Locations: []ftypes.Location{
						{
							StartLine: 6,
							EndLine:   6,
						},
					},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.lockfile",
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

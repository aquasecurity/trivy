package lockfile

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
			inputFile: "testdata/happy.lockfile",
			want: []types.Library{
				{
					ID:       "cglib:cglib-nodep:2.1.2",
					Name:     "cglib:cglib-nodep",
					Version:  "2.1.2",
					Indirect: true,
					Locations: []types.Location{
						{
							StartLine: 4,
							EndLine:   4,
						},
					},
				},
				{
					ID:       "org.springframework:spring-asm:3.1.3.RELEASE",
					Name:     "org.springframework:spring-asm",
					Version:  "3.1.3.RELEASE",
					Indirect: true,
					Locations: []types.Location{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					ID:       "org.springframework:spring-beans:5.0.5.RELEASE",
					Name:     "org.springframework:spring-beans",
					Version:  "5.0.5.RELEASE",
					Indirect: true,
					Locations: []types.Location{
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

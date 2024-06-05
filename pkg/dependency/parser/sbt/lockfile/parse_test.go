package lockfile

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"os"
	"sort"
	"strings"
	"testing"
)

func TestParser_Parse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
	}{
		{
			name:      "v1 happy path",
			inputFile: "testdata/v1_happy.sbt.lock",
			want: []ftypes.Package{
				{
					ID:      "org.apache.commons:commons-lang3:3.9",
					Name:    "org.apache.commons:commons-lang3",
					Version: "3.9",
					Locations: []ftypes.Location{
						{
							StartLine: 10,
							EndLine:   25,
						},
					},
				},
				{
					ID:      "org.scala-lang:scala-library:2.12.10",
					Name:    "org.scala-lang:scala-library",
					Version: "2.12.10",
					Locations: []ftypes.Location{
						{
							StartLine: 26,
							EndLine:   41,
						},
					},
				},
				{
					ID:      "org.typelevel:cats-core_2.12:2.9.0",
					Name:    "org.typelevel:cats-core_2.12",
					Version: "2.9.0",
					Locations: []ftypes.Location{
						{
							StartLine: 42,
							EndLine:   57,
						},
					},
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/empty.sbt.lock",
			want:      nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			assert.NoError(t, err)

			libs, _, err := parser.Parse(f)
			assert.Equal(t, nil, err)

			sortLibs(libs)
			assert.Equal(t, tt.want, libs)
		})
	}
}

func sortLibs(libs []ftypes.Package) {
	sort.Slice(libs, func(i, j int) bool {
		ret := strings.Compare(libs[i].Name, libs[j].Name)
		if ret == 0 {
			return libs[i].Version < libs[j].Version
		}
		return ret < 0
	})
}

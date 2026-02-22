package verification_metadata

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
			inputFile: "testdata/verification-metadata-happy.xml",
			want: []ftypes.Package{
				{
					ID:           "ch.qos.logback:logback-classic:1.5.32",
					Name:         "ch.qos.logback:logback-classic",
					Version:      "1.5.32",
					Relationship: ftypes.RelationshipUnknown,
				},
			},
		},
		{
			name:      "empty",
			inputFile: "testdata/verification-metadata-empty.xml",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parser := NewParser()
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			pkgs, _, _ := parser.Parse(t.Context(), f)
			sort.Sort(ftypes.Packages(pkgs))
			assert.Equal(t, tt.want, pkgs)
		})
	}
}

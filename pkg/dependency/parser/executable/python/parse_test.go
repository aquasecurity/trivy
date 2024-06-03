package pythonparser

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Package
		wantDep   []types.Dependency
		wantErr   string
	}{
		{
			name:      "ELF2.7",
			inputFile: "testdata/python2.7.elf",
			want: []types.Package{
				{
					ID:      "python@2.7.18",
					Name:    "python",
					Version: "2.7.18",
				},
			},
		},
		{
			name:      "ELF3.9",
			inputFile: "testdata/python3.9.elf",
			want: []types.Package{
				{
					ID:      "python@3.9.19",
					Name:    "python",
					Version: "3.9.19",
				},
			},
		},
		{
			name:      "ELF3.10",
			inputFile: "testdata/python3.10.elf",
			want: []types.Package{
				{
					ID:      "python@3.10.12",
					Name:    "python",
					Version: "3.10.12",
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/dummy",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			parser := NewParser()
			got, _, err := parser.Parse(f)
			if tt.wantErr != "" {
				require.Error(t, err)
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

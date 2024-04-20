package binary

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantDep   []types.Dependency
		wantErr   string
	}{
		{
			name:      "ELF2.7",
			inputFile: "testdata/python2.7.elf",
			want: []types.Library{
				{
					ID: 	 "python@2.7.18",
					Name:    "python",
					Version: "2.7.18",
				},
			},
		},
		{
			name:      "ELF3.9",
			inputFile: "testdata/python3.9.elf",
			want: []types.Library{
				{
					ID: 	 "python@3.9.19",
					Name:    "python",
					Version: "3.9.19",
				},
			},
		},
		{
			name:      "ELF3.10",
			inputFile: "testdata/python3.10.elf",
			want: []types.Library{
				{
					ID: 	 "python@3.10.12",
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
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

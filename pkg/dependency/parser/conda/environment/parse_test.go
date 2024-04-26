package environment_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/environment"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []types.Library
		wantErr string
	}{
		{
			name:  "happy path",
			input: "testdata/happy.yaml",
			want: []types.Library{
				{
					Name: "_libgcc_mutex",
					Locations: types.Locations{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					Name:    "_openmp_mutex",
					Version: "5.1",
					Locations: types.Locations{
						{
							StartLine: 6,
							EndLine:   6,
						},
					},
				}, {
					Name:    "blas",
					Version: "1.0",
					Locations: types.Locations{
						{
							StartLine: 7,
							EndLine:   7,
						},
					},
				},
				{
					Name:    "bzip2",
					Version: "1.0.8",
					Locations: types.Locations{
						{
							StartLine: 8,
							EndLine:   8,
						},
					},
				},
			},
		},
		{
			name:    "invalid_json",
			input:   "testdata/invalid.yaml",
			wantErr: "unable to decode conda environment.yml file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.input)
			require.NoError(t, err)
			defer f.Close()

			got, _, err := environment.NewParser().Parse(f)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

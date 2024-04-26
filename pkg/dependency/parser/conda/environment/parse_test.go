package environment_test

import (
	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/environment"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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
					Name:    "_libgcc_mutex",
					Version: "0.1",
				},
			},
		},
		{
			name:    "invalid_json",
			input:   "testdata/invalid_json.json",
			wantErr: "JSON decode error: invalid character",
		},
		{
			name:    "invalid_package",
			input:   "testdata/invalid_package.json",
			wantErr: "unable to parse conda package",
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

package meta_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/meta"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    []ftypes.Package
		wantErr string
	}{
		{
			name:  "_libgcc_mutex",
			input: "testdata/_libgcc_mutex-0.1-main.json",
			want: []ftypes.Package{
				{
					Name:    "_libgcc_mutex",
					Version: "0.1",
				},
			},
		},
		{
			name:  "libgomp",
			input: "testdata/libgomp-11.2.0-h1234567_1.json",
			want: []ftypes.Package{
				{
					Name:     "libgomp",
					Version:  "11.2.0",
					Licenses: []string{"GPL-3.0-only WITH GCC-exception-3.1"},
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

			got, _, err := meta.NewParser().Parse(f)

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

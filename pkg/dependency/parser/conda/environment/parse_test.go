package environment_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/conda/environment"
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
			name:  "happy path",
			input: "testdata/happy.yaml",
			want: []ftypes.Package{
				{
					Name: "_openmp_mutex",
					Locations: ftypes.Locations{
						{
							StartLine: 6,
							EndLine:   6,
						},
					},
				},
				{
					Name:    "blas",
					Version: "1.0",
					Locations: ftypes.Locations{
						{
							StartLine: 5,
							EndLine:   5,
						},
					},
				},
				{
					Name:    "bzip2",
					Version: "1.0.8",
					Locations: ftypes.Locations{
						{
							StartLine: 19,
							EndLine:   19,
						},
					},
				},
				{
					Name:    "ca-certificates",
					Version: "2024.2",
					Locations: ftypes.Locations{
						{
							StartLine: 7,
							EndLine:   7,
						},
					},
				},
				{
					Name: "ld_impl_linux-aarch64",
					Locations: ftypes.Locations{
						{
							StartLine: 8,
							EndLine:   8,
						},
					},
				},
				{
					Name: "libblas",
					Locations: ftypes.Locations{
						{
							StartLine: 9,
							EndLine:   9,
						},
					},
				},
				{
					Name: "libcblas",
					Locations: ftypes.Locations{
						{
							StartLine: 10,
							EndLine:   10,
						},
					},
				},
				{
					Name:    "libexpat",
					Version: "2.6.2",
					Locations: ftypes.Locations{
						{
							StartLine: 11,
							EndLine:   11,
						},
					},
				},
				{
					Name:    "libffi",
					Version: "3.4.2",
					Locations: ftypes.Locations{
						{
							StartLine: 12,
							EndLine:   12,
						},
					},
				},
				{
					Name: "libgcc-ng",
					Locations: ftypes.Locations{
						{
							StartLine: 13,
							EndLine:   13,
						},
					},
				},
				{
					Name: "libgfortran-ng",
					Locations: ftypes.Locations{
						{
							StartLine: 14,
							EndLine:   14,
						},
					},
				},
				{
					Name: "libgfortran5",
					Locations: ftypes.Locations{
						{
							StartLine: 15,
							EndLine:   15,
						},
					},
				},
				{
					Name:    "libgomp",
					Version: "13.2.0",
					Locations: ftypes.Locations{
						{
							StartLine: 16,
							EndLine:   16,
						},
					},
				},
				{
					Name: "liblapack",
					Locations: ftypes.Locations{
						{
							StartLine: 17,
							EndLine:   17,
						},
					},
				},
				{
					Name:    "libnsl",
					Version: "2.0.1",
					Locations: ftypes.Locations{
						{
							StartLine: 18,
							EndLine:   18,
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

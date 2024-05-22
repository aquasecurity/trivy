package gemspec_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/ruby/gemspec"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []ftypes.Package
		wantErr   string
	}{
		{
			name:      "happy",
			inputFile: "testdata/normal00.gemspec",
			want: []ftypes.Package{
				{
					Name:     "rake",
					Version:  "13.0.3",
					Licenses: []string{"MIT"},
				},
			},
		},
		{
			name:      "another variable name",
			inputFile: "testdata/normal01.gemspec",
			want: []ftypes.Package{
				{
					Name:    "async",
					Version: "1.25.0",
				},
			},
		},
		{
			name:      "license",
			inputFile: "testdata/license.gemspec",
			want: []ftypes.Package{
				{
					Name:     "async",
					Version:  "1.25.0",
					Licenses: []string{"MIT"},
				},
			},
		},
		{
			name:      "multiple licenses",
			inputFile: "testdata/multiple_licenses.gemspec",
			want: []ftypes.Package{
				{
					Name:    "test-unit",
					Version: "3.3.7",
					Licenses: []string{
						"Ruby",
						"BSDL",
						"PSFL",
					},
				},
			},
		},
		{
			name:      "malformed variable name",
			inputFile: "testdata/malformed00.gemspec",
			wantErr:   "failed to parse gemspec",
		},
		{
			name:      "missing version",
			inputFile: "testdata/malformed01.gemspec",
			wantErr:   "failed to parse gemspec",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := gemspec.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

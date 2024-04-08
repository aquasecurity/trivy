package gemspec_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/ruby/gemspec"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "happy",
			inputFile: "testdata/normal00.gemspec",
			want: []types.Library{{
				Name:    "rake",
				Version: "13.0.3",
				License: "MIT",
			}},
		},
		{
			name:      "another variable name",
			inputFile: "testdata/normal01.gemspec",
			want: []types.Library{{
				Name:    "async",
				Version: "1.25.0",
			}},
		},
		{
			name:      "license",
			inputFile: "testdata/license.gemspec",
			want: []types.Library{{
				Name:    "async",
				Version: "1.25.0",
				License: "MIT",
			}},
		},
		{
			name:      "multiple licenses",
			inputFile: "testdata/multiple_licenses.gemspec",
			want: []types.Library{{
				Name:    "test-unit",
				Version: "3.3.7",
				License: "Ruby, BSDL, PSFL",
			}},
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
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

package config_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/nuget/config"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
)

func TestParse(t *testing.T) {
	tests := []struct {
		name      string // Test input file
		inputFile string
		want      []types.Library
		wantErr   string
	}{
		{
			name:      "Config",
			inputFile: "testdata/packages.config",
			want: []types.Library{
				{Name: "Newtonsoft.Json", Version: "6.0.4"},
				{Name: "Microsoft.AspNet.WebApi", Version: "5.2.2"},
			},
		},
		{
			name:      "with development dependency",
			inputFile: "testdata/dev_dependency.config",
			want: []types.Library{
				{Name: "Newtonsoft.Json", Version: "8.0.3"},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/malformed_xml.config",
			wantErr:   "failed to decode .config file: XML syntax error on line 5: unexpected EOF",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)

			got, _, err := config.NewParser().Parse(f)
			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.ElementsMatch(t, tt.want, got)
		})
	}
}

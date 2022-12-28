package licensing

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_licenseAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "Licensed C file",
			filePath: "testdata/licensed.c",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeHeader,
						FilePath: "testdata/licensed.c",
						Findings: []types.LicenseFinding{
							{
								Name:       "AGPL-3.0",
								Confidence: 1,
								Link:       "https://spdx.org/licenses/AGPL-3.0.html",
							},
						},
					},
				},
			},
		},
		{
			name:     "Non human readable binary file",
			filePath: "testdata/binaryfile",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.filePath)
			require.NoError(t, err)
			defer f.Close()

			fi, err := f.Stat()
			require.NoError(t, err)

			a := licenseFileAnalyzer{}
			got, err := a.Analyze(context.TODO(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
				Info:     fi,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}

}

func Test_licenseAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "C file with license",
			filePath: "testdata/licensed.c",
			want:     true,
		},
		{
			name:     "C file without license",
			filePath: "testdata/unlicensed.c",
			want:     true,
		},
		{
			name:     "Unreadable file",
			filePath: "testdata/binaryfile",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := licenseFileAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

package dpkg

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_dpkgLicenseAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name                 string
		filePath             string
		inputContentFilePath string
		wantLicense          *analyzer.AnalysisResult
	}{
		{
			name:                 "machine-readable format",
			filePath:             "usr/share/doc/zlib1g/copyright",
			inputContentFilePath: "testdata/license-pattern-and-classifier-copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     string(types.DpkgLicensePostHandler),
						FilePath: "usr/share/doc/zlib1g/copyright",
						Data:     "Zlib",
					},
				},
			},
		},
		{
			name:                 "common-licenses format",
			filePath:             "usr/share/doc/adduser/copyright",
			inputContentFilePath: "testdata/common-license-copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     string(types.DpkgLicensePostHandler),
						FilePath: "usr/share/doc/adduser/copyright",
						Data:     "GPL-2",
					},
				},
			},
		},
		{
			name:                 "machine-readable and common-licenses format",
			filePath:             "usr/share/doc/apt/copyright",
			inputContentFilePath: "testdata/all-patterns-copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     string(types.DpkgLicensePostHandler),
						FilePath: "usr/share/doc/apt/copyright",
						Data:     "GPLv2+, GPL-2",
					},
				},
			},
		},
		{
			name:                 "no license found",
			filePath:             "usr/share/doc/tzdata/copyright",
			inputContentFilePath: "testdata/no-license-copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     string(types.DpkgLicensePostHandler),
						FilePath: "usr/share/doc/tzdata/copyright",
						Data:     "Unknown",
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputContentFilePath)
			require.NoError(t, err)

			input := analyzer.AnalysisInput{
				Content:  f,
				FilePath: tt.filePath,
			}
			a := dpkgLicenseAnalyzer{}

			license, err := a.Analyze(context.Background(), input)
			require.NoError(t, err)
			assert.Equal(t, tt.wantLicense, license)
		})
	}
}

func Test_dpkgLicenseAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "usr/share/doc/eject/copyright",
			want:     true,
		},
		{
			name:     "bad prefix",
			filePath: "usr/share/doc/eject/copyright/file",
			want:     false,
		},
		{
			name:     "bad file name",
			filePath: "usr/share/doc/eject/copyright/foo",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := dpkgLicenseAnalyzer{}
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}

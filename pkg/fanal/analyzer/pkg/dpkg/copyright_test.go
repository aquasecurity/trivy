package dpkg

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
)

func TestDpkgLicensesAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name              string
		copyrightFilePath string
		wantLicense       *analyzer.AnalysisResult
	}{
		{
			name:              "happy path. There are 'License:' pattern and licenseclassifier",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/zlib1g/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "zlib1g",
						Data:     "Zlib",
					},
				},
			},
		},
		{
			name:              "happy path. There is Common license",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/adduser/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "adduser",
						Data:     "GPL-2, GPL-2.0",
					},
				},
			},
		},
		{
			name:              "happy path. There are Common license, 'License:' pattern and licenseclassifier",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/apt/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "apt",
						Data:     "GPLv2+, GPL-2, GPL-2.0",
					},
				},
			},
		},
		{
			name:              "happy path. Licenses not found",
			copyrightFilePath: "testdata/copyrightFiles/usr/share/doc/tzdata/copyright",
			wantLicense: &analyzer.AnalysisResult{
				CustomResources: []types.CustomResource{
					{
						Type:     LicenseAdder,
						FilePath: "tzdata",
						Data:     "Unknown",
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			f, err := os.Open(test.copyrightFilePath)
			if err != nil {
				t.Error("unable to read test file")
			}

			input := analyzer.AnalysisInput{
				Content:  f,
				FilePath: strings.TrimPrefix(test.copyrightFilePath, "testdata/copyrightFiles/"),
			}
			a := dpkgLicensesAnalyzer{}

			license, _ := a.Analyze(context.Background(), input)
			assert.Equal(t, test.wantLicense, license)
		})
	}
}

func TestDpkgLicencesAnalyzer_Required(t *testing.T) {
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
			name:     "sad path. Wrong path",
			filePath: "/usr/share/doc/library/eject/copyright",
			want:     false,
		},
		{
			name:     "sad path. Wrong prefix",
			filePath: "/usr/share/doc/eject/copyright/file",
			want:     false,
		},
		{
			name:     "sad path. Wrong suffix",
			filePath: "/usr/share/doc/eject/copyright",
			want:     false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			a := dpkgLicensesAnalyzer{}
			assert.Equal(t, test.want, a.Required(test.filePath, nil))
		})
	}
}

func TestDpkgAnalyzer_getPkgNameFromLicenseFilePath(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		wantPkg  string
	}{
		{
			name:     "happy path",
			filePath: "usr/share/doc/eject/copyright",
			wantPkg:  "eject",
		},
		{
			name:     "sad path",
			filePath: "usr/share/doc/library/eject/copyright",
			wantPkg:  "",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert.Equal(t, test.wantPkg, getPkgNameFromLicenseFilePath(test.filePath))
		})
	}
}

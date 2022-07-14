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
		name     string
		filePath string
		testFile string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "machine-readable format",
			filePath: "usr/share/doc/zlib1g/copyright",
			testFile: "testdata/license-pattern-and-classifier-copyright",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeDpkg,
						FilePath: "usr/share/doc/zlib1g/copyright",
						Findings: []types.LicenseFinding{
							{Name: "Zlib"},
						},
						PkgName: "zlib1g",
					},
				},
			},
		},
		{
			name:     "common-licenses format",
			filePath: "usr/share/doc/adduser/copyright",
			testFile: "testdata/common-license-copyright",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeDpkg,
						FilePath: "usr/share/doc/adduser/copyright",
						Findings: []types.LicenseFinding{
							{Name: "GPL-2.0"},
						},
						PkgName: "adduser",
					},
				},
			},
		},
		{
			name:     "machine-readable and common-licenses format",
			filePath: "usr/share/doc/apt/copyright",
			testFile: "testdata/all-patterns-copyright",
			want: &analyzer.AnalysisResult{
				Licenses: []types.LicenseFile{
					{
						Type:     types.LicenseTypeDpkg,
						FilePath: "usr/share/doc/apt/copyright",
						Findings: []types.LicenseFinding{
							{Name: "GPL-2.0"},
						},
						PkgName: "apt",
					},
				},
			},
		},
		{
			name:     "no license found",
			filePath: "usr/share/doc/tzdata/copyright",
			testFile: "testdata/no-license-copyright",
			want:     nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.testFile)
			require.NoError(t, err)

			input := analyzer.AnalysisInput{
				Content:  f,
				FilePath: tt.filePath,
			}
			a := dpkgLicenseAnalyzer{}

			license, err := a.Analyze(context.Background(), input)
			require.NoError(t, err)
			assert.Equal(t, tt.want, license)
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

func Test_dpkgLicenseAnalyzer_splitLicenses(t *testing.T) {
	tests := []struct {
		name         string
		input        string
		wantLicenses []string
	}{
		{
			name:         "comma",
			input:        "GPL-1+, GPL-2",
			wantLicenses: []string{"GPL-1.0", "GPL-2.0"},
		},
		{
			name:         "or with spaces",
			input:        "GPL-1+ or Artistic or Artistic-dist",
			wantLicenses: []string{"GPL-1.0", "Artistic", "Artistic-dist"},
		},
		{
			name:         "or with '_'",
			input:        "LGPLv3+_or_GPLv2+",
			wantLicenses: []string{"LGPLv3+", "GPL-2.0"},
		},
		{
			name:         "and with spaces",
			input:        "BSD-3-CLAUSE and GPL-2",
			wantLicenses: []string{"BSD-3-Clause", "GPL-2.0"},
		},
		{
			name:         "or + and",
			input:        "GPL-1+ or Artistic, and BSD-4-clause-POWERDOG",
			wantLicenses: []string{"GPL-1.0", "Artistic", "BSD-4-clause-POWERDOG"},
		},
		{
			name:         "without split",
			input:        "GPL 2.0",
			wantLicenses: []string{"GPL-2.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			licenses := splitLicenses(tt.input)
			assert.Equal(t, tt.wantLicenses, licenses)
		})
	}
}

package licensing

import (
	"context"
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_AnalyzeLicenses(t *testing.T) {
	tests := []struct {
		name                 string
		filePath             string
		expectedHandlerFiles int
		riskThreshold        int
		ignoredLicenses      []string
	}{
		{
			name:                 "Licensed C file",
			filePath:             "testdata/licensed.c",
			expectedHandlerFiles: 1,
			riskThreshold:        7,
		},
		{
			name:                 "Another Licensed C file",
			filePath:             "testdata/another_licensed.c",
			expectedHandlerFiles: 1,
			riskThreshold:        7,
		},
		{
			name:                 "CSS File",
			filePath:             "testdata/styles.css",
			expectedHandlerFiles: 1,
			riskThreshold:        7,
		},
		{
			name:                 "Unlicensed C file",
			filePath:             "testdata/unlicensed.c",
			expectedHandlerFiles: 0,
			riskThreshold:        4,
		},
		{
			name:                 "Licensed C with config ignoring license",
			filePath:             "testdata/licensed.c",
			ignoredLicenses:      []string{"BSD-3-Clause", "AGPL-3.0"},
			expectedHandlerFiles: 0,
			riskThreshold:        4,
		},
		{
			name:                 "Non human readable binary file",
			filePath:             "testdata/binaryfile",
			expectedHandlerFiles: 0,
			riskThreshold:        4,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newLicenseScanner(ScannerOption{
				RiskThreshold: tt.riskThreshold, IgnoredLicenses: tt.ignoredLicenses,
			})
			require.NoError(t, err)
			content, err := os.Open(tt.filePath)
			require.NoError(t, err)
			fi, err := content.Stat()
			require.NoError(t, err)

			got, err := a.Analyze(context.TODO(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  content,
				Info:     fi,
			})
			require.NoError(t, err)

			if tt.expectedHandlerFiles > 0 {
				assert.Len(t, got.Licenses, tt.expectedHandlerFiles)
			} else {
				assert.Nil(t, got)
			}
		})
	}

}

func Test_LicenseAnalysisRequired(t *testing.T) {
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
		{
			name:     "Image file",
			filePath: "testdata/picture.png",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newLicenseScanner(ScannerOption{RiskThreshold: 7, IgnoredLicenses: []string{}})
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}

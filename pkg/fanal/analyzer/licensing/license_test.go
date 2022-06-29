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
		name                       string
		filePath                   string
		expectedIdentifiedLicenses int
		expectedLicense            string
	}{
		{
			name:                       "Licensed C file",
			filePath:                   "testdata/licensed.c",
			expectedLicense:            "AGPL-3.0",
			expectedIdentifiedLicenses: 1,
		},
		{
			name:                       "Another Licensed C file",
			filePath:                   "testdata/another_licensed.c",
			expectedLicense:            "BSL-1.0",
			expectedIdentifiedLicenses: 1,
		},
		{
			name:                       "CSS File",
			filePath:                   "testdata/styles.css",
			expectedLicense:            "Apache-2.0",
			expectedIdentifiedLicenses: 1,
		},
		{
			name:                       "Unlicensed C file",
			filePath:                   "testdata/unlicensed.c",
			expectedLicense:            "",
			expectedIdentifiedLicenses: 0,
		},
		{
			name:                       "Non human readable binary file",
			filePath:                   "testdata/binaryfile",
			expectedLicense:            "",
			expectedIdentifiedLicenses: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a, err := newLicenseScanner(ScannerOption{})
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

			if tt.expectedIdentifiedLicenses > 0 {
				assert.Len(t, got.Licenses, tt.expectedIdentifiedLicenses)
				assert.Equal(t, tt.expectedLicense, got.Licenses[0].Findings[0].License)
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
			a, err := newLicenseScanner(ScannerOption{})
			require.NoError(t, err)

			fi, err := os.Stat(tt.filePath)
			require.NoError(t, err)

			got := a.Required(tt.filePath, fi)
			assert.Equal(t, tt.want, got)
		})
	}
}

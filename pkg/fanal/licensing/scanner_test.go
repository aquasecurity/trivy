package licensing

import (
	"fmt"
	"io/fs"
	"math"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/liamg/memoryfs"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_LicenseScanning(t *testing.T) {

	tests := []struct {
		name             string
		filePath         string
		expectLicense    bool
		packageName      string
		expectedFindings []types.LicenseFinding
		riskThreshold    int
	}{
		{
			name:          "C file with AGPL-3.0",
			filePath:      "testdata/licensed.c",
			expectLicense: true,
			expectedFindings: []types.LicenseFinding{
				{
					License:                     "AGPL-3.0",
					GoogleLicenseClassification: "forbidden",
					Confidence:                  0.98,
				},
			},
		},
		{
			name:             "C file with AGPL-3.0 with 100 confidence",
			filePath:         "testdata/licensed.c",
			expectLicense:    false,
			expectedFindings: []types.LicenseFinding{},
		},
		{
			name:             "C file with ignored AGPL-3.0",
			filePath:         "testdata/licensed.c",
			expectLicense:    false,
			expectedFindings: []types.LicenseFinding{},
			riskThreshold:    7,
		},
		{
			name:          "C file with no license",
			filePath:      "testdata/unlicensed.c",
			expectLicense: false,
		},
		{
			name:          "Creative commons License file",
			filePath:      "testdata/LICENSE_creativecommons",
			expectLicense: true,
			expectedFindings: []types.LicenseFinding{
				{
					License:                     "Commons-Clause",
					GoogleLicenseClassification: "forbidden",
					Confidence:                  0.98,
				},
			},
		},
		{
			name:          "Apache-2.0 CSS File",
			filePath:      "testdata/styles.css",
			expectLicense: true,
			riskThreshold: 7,
			expectedFindings: []types.LicenseFinding{
				{
					License:                     "Apache-2.0",
					GoogleLicenseClassification: "notice",
					Confidence:                  1,
				},
			},
		},
		{
			name:          "Package folder identifies package",
			filePath:      "testdata/callsites",
			expectLicense: true,
			packageName:   "callsites",
			expectedFindings: []types.LicenseFinding{
				{
					License:                     "MIT",
					GoogleLicenseClassification: "notice",
					Confidence:                  0.98,
				},
				{
					License:                     "MIT-0",
					GoogleLicenseClassification: "unknown",
					Confidence:                  0.98,
				},
			},
			riskThreshold: 7,
		},
		{
			name:          "Apache 2 License file",
			filePath:      "testdata/LICENSE_apache2",
			expectLicense: false,
		},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%#v", tt.name), func(t *testing.T) {

			threshold := int(math.Max(float64(tt.riskThreshold), 4))

			scanner, err := NewScanner(threshold, []string{})
			require.NoError(t, err)

			var testFS fs.FS
			f, err := os.Stat(tt.filePath)
			require.NoError(t, err)
			if f.IsDir() {
				testFS = os.DirFS(tt.filePath)
			} else {
				memfs := memoryfs.New()
				if filepath.Dir(tt.filePath) != "." {
					err = memfs.MkdirAll(filepath.Dir(tt.filePath), os.ModePerm)
					require.NoError(t, err)
				}
				content, err := os.ReadFile(tt.filePath)
				require.NoError(t, err)
				err = memfs.WriteFile(tt.filePath, content, os.ModePerm)
				testFS = memfs
			}

			licenses, err := scanner.ScanFS(testFS)
			require.NoError(t, err)

			if tt.expectLicense {
				assert.NotNil(t, licenses)
				require.Len(t, licenses, 1)
				license := licenses[0]
				assert.Len(t, license.Findings, len(tt.expectedFindings))

				// sort findings for consistent checking
				sort.Slice(license.Findings, func(i, j int) bool {
					return license.Findings[i].License < license.Findings[j].License
				})

				for i, f := range tt.expectedFindings {
					lf := license.Findings[i]
					assert.Equal(t, f.License, lf.License)
					assert.Equal(t, f.GoogleLicenseClassification, lf.GoogleLicenseClassification)
					assert.Greater(t, lf.Confidence, 0.8)
				}
			}
		})

	}
}

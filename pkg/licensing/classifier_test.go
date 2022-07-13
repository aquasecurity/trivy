package licensing_test

import (
	"os"
	"testing"

	"github.com/aquasecurity/trivy/pkg/licensing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestClassifier_Classify(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     types.LicenseFile
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "C file with AGPL-3.0",
			filePath: "testdata/licensed.c",
			want: types.LicenseFile{
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
		{
			name:     "C file with no license",
			filePath: "testdata/unlicensed.c",
			want: types.LicenseFile{
				FilePath: "testdata/unlicensed.c",
			},
		},
		{
			name:     "Creative commons License file",
			filePath: "testdata/LICENSE_creativecommons",
			want: types.LicenseFile{
				Type:     types.LicenseTypeFile,
				FilePath: "testdata/LICENSE_creativecommons",
				Findings: []types.LicenseFinding{
					{
						Name:       "Commons-Clause",
						Confidence: 1,
						Link:       "https://spdx.org/licenses/Commons-Clause.html",
					},
				},
			},
		},
		{
			name:     "Apache-2.0 CSS File",
			filePath: "testdata/styles.css",
			want: types.LicenseFile{
				Type:     types.LicenseTypeFile,
				FilePath: "testdata/styles.css",
				Findings: []types.LicenseFinding{
					{
						Name:       "Apache-2.0",
						Confidence: 1,
						Link:       "https://spdx.org/licenses/Apache-2.0.html",
					},
				},
			},
		},
		{
			name:     "Apache 2 License file",
			filePath: "testdata/LICENSE_apache2",
			want: types.LicenseFile{
				Type:     types.LicenseTypeFile,
				FilePath: "testdata/LICENSE_apache2",
				Findings: []types.LicenseFinding{
					{
						Name:       "Apache-2.0",
						Confidence: 1,
						Link:       "https://spdx.org/licenses/Apache-2.0.html",
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents, err := os.ReadFile(tt.filePath)
			require.NoError(t, err)

			got := licensing.Classify(tt.filePath, contents)
			assert.Equal(t, tt.want, got)
		})
	}
}

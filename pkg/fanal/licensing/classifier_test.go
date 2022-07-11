package licensing_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/licensing"
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
				FilePath: "testdata/licensed.c",
				Findings: []types.LicenseFinding{
					{
						License:    "AGPL-3.0",
						Confidence: 0.98,
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
				FilePath: "testdata/LICENSE_creativecommons",
				Findings: []types.LicenseFinding{
					{
						License:    "Commons-Clause",
						Confidence: 0.98,
					},
				},
			},
		},
		{
			name:     "Apache-2.0 CSS File",
			filePath: "testdata/styles.css",
			want: types.LicenseFile{
				FilePath: "testdata/styles.css",
				Findings: []types.LicenseFinding{
					{
						License:    "Apache-2.0",
						Confidence: 1,
					},
				},
			},
		},
		{
			name:     "Apache 2 License file",
			filePath: "testdata/LICENSE_apache2",
			want: types.LicenseFile{
				FilePath: "testdata/styles.css",
				Findings: []types.LicenseFinding{
					{
						License:    "Apache-2.0",
						Confidence: 1,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c, err := licensing.NewClassifier()
			require.NoError(t, err)

			contents, err := os.ReadFile(tt.filePath)
			require.NoError(t, err)

			got := c.Classify(tt.filePath, contents)
			assert.Equal(t, tt.want, got)
		})
	}
}

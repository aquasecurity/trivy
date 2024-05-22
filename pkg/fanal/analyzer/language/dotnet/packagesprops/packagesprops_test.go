package packagesprops

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_packagesPropsAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path packages props",
			inputFile: "testdata/Packages.props",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PackagesProps,
						FilePath: "testdata/Packages.props",
						Packages: types.Packages{
							{
								ID:      "Package1@22.1.4",
								Name:    "Package1",
								Version: "22.1.4",
							},
							{
								ID:      "Package2@2.3.0",
								Name:    "Package2",
								Version: "2.3.0",
							},
						},
					},
				},
			},
		},
		{
			name:      "happy path directory packages props",
			inputFile: "testdata/Directory.Packages.props",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PackagesProps,
						FilePath: "testdata/Directory.Packages.props",
						Packages: types.Packages{
							{
								ID:      "Package1@4.2.1",
								Name:    "Package1",
								Version: "4.2.1",
							},
							{
								ID:      "Package2@8.2.0",
								Name:    "Package2",
								Version: "8.2.0",
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/invalid.txt",
			wantErr:   "*Packages.props dependencies analysis error",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := packagesPropsAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_packagesPropsAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "directory packages props",
			filePath: "test/Directory.Packages.props",
			want:     true,
		},
		{
			name:     "packages props",
			filePath: "test/Packages.props",
			want:     true,
		},
		{
			name:     "packages props lower case",
			filePath: "test/packages.props",
			want:     true,
		},
		{
			name:     "zip",
			filePath: "test.zip",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := packagesPropsAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

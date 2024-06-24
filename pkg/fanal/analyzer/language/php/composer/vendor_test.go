package composer

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_composerVendorAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/composer-vendor/happy/installed.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.ComposerVendor,
						FilePath: "testdata/composer-vendor/happy/installed.json",
						Packages: []types.Package{
							{
								ID:           "pear/log@1.13.3",
								Name:         "pear/log",
								Version:      "1.13.3",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Licenses:     []string{"MIT"},
								Locations: []types.Location{
									{
										StartLine: 3,
										EndLine:   65,
									},
								},
								DependsOn: []string{"pear/pear_exception@v1.0.2"},
							},
							{
								ID:           "pear/pear_exception@v1.0.2",
								Name:         "pear/pear_exception",
								Version:      "v1.0.2",
								Indirect:     false,
								Relationship: types.RelationshipUnknown,
								Licenses:     []string{"BSD-2-Clause"},
								Locations: []types.Location{
									{
										StartLine: 66,
										EndLine:   127,
									},
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/composer-vendor/sad/installed.json",
			wantErr:   "decode error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer func() {
				err = f.Close()
				require.NoError(t, err)
			}()

			a := composerVendorAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if tt.wantErr != "" {
				require.ErrorContains(t, err, tt.wantErr)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.want, got)
		})
	}
}

func Test_composerVendorAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "app/vendor/composer/installed.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "composer.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := composerVendorAnalyzer{}
			got := a.Required(tt.filePath, nil)
			require.Equal(t, tt.want, got)
		})
	}
}

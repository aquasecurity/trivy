package pkg

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_nodePkgLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		inputFile       string
		includeChecksum bool
		want            *analyzer.AnalysisResult
		wantErr         string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/package.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "testdata/package.json",
						Libraries: []types.Package{
							{
								ID:       "lodash@5.0.0",
								Name:     "lodash",
								Version:  "5.0.0",
								Licenses: []string{"MIT"},
								FilePath: "testdata/package.json",
							},
						},
					},
				},
			},
		},
		{
			name:            "happy path with checksum",
			inputFile:       "testdata/package.json",
			includeChecksum: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "testdata/package.json",
						Libraries: []types.Package{
							{
								ID:       "lodash@5.0.0",
								Name:     "lodash",
								Version:  "5.0.0",
								Licenses: []string{"MIT"},
								FilePath: "testdata/package.json",
								Digest:   "sha1:901a7b55410321c4d35543506cff2a8613ef5aa2",
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/noname.json",
			wantErr:   "unable to parse",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := nodePkgLibraryAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
				Options:  analyzer.AnalysisOptions{FileChecksum: tt.includeChecksum},
			})

			if tt.wantErr != "" {
				require.NotNil(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_nodePkgLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "nodejs/package.json",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "nodejs/package-lock.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := nodePkgLibraryAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

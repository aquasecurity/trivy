package pkg

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Test_nodePkgLibraryAnalyzer_Analyze(t *testing.T) {
	type args struct {
		target analyzer.AnalysisTarget
	}
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/package.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.NodePkg,
						FilePath: "testdata/package.json",
						Libraries: []types.LibraryInfo{
							{
								FilePath: "testdata/package.json",
								Library: godeptypes.Library{
									Name:    "lodash",
									Version: "5.0.0",
									License: "MIT",
								},
							},
						},
					},
				},
			},
		},
		{
			name:      "sad path",
			inputFile: "testdata/noname.json",
			wantErr:   "unable to parse testdata/noname.json",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := os.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := nodePkgLibraryAnalyzer{}
			got, err := a.Analyze(analyzer.AnalysisTarget{
				FilePath: tt.inputFile,
				Content:  b,
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

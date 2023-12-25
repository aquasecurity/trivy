package packaging

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_packagingAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name            string
		inputFile       string
		includeChecksum bool
		want            *analyzer.AnalysisResult
		wantErr         string
	}{
		{
			name:      "egg zip",
			inputFile: "testdata/kitchen-1.2.6-py2.7.egg",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "testdata/kitchen-1.2.6-py2.7.egg",
						Libraries: types.Packages{
							{
								Name:     "kitchen",
								Version:  "1.2.6",
								Licenses: []string{"LGPLv2+"},
								FilePath: "testdata/kitchen-1.2.6-py2.7.egg",
							},
						},
					},
				},
			},
		},
		{
			name:            "egg-info",
			inputFile:       "testdata/happy.egg-info/PKG-INFO",
			includeChecksum: true,
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "testdata/happy.egg-info/PKG-INFO",
						Libraries: types.Packages{
							{
								Name:     "distlib",
								Version:  "0.3.1",
								Licenses: []string{"Python license"},
								FilePath: "testdata/happy.egg-info/PKG-INFO",
								Digest:   "sha1:d9d89d8ed3b2b683767c96814c9c5d3e57ef2e1b",
							},
						},
					},
				},
			},
		},
		{
			name:      "egg-info license classifiers",
			inputFile: "testdata/classifier-license.egg-info/PKG-INFO",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "testdata/classifier-license.egg-info/PKG-INFO",
						Libraries: types.Packages{
							{
								Name:     "setuptools",
								Version:  "51.3.3",
								Licenses: []string{"MIT License"},
								FilePath: "testdata/classifier-license.egg-info/PKG-INFO",
							},
						},
					},
				},
			},
		},
		{
			name:      "dist-info license classifiers",
			inputFile: "testdata/classifier-license.dist-info/METADATA",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "testdata/classifier-license.dist-info/METADATA",
						Libraries: types.Packages{
							{
								Name:     "setuptools",
								Version:  "51.3.3",
								Licenses: []string{"MIT License"},
								FilePath: "testdata/classifier-license.dist-info/METADATA",
							},
						},
					},
				},
			},
		},
		{
			name:      "wheel",
			inputFile: "testdata/happy.dist-info/METADATA",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "testdata/happy.dist-info/METADATA",
						Libraries: types.Packages{
							{
								Name:     "distlib",
								Version:  "0.3.1",
								Licenses: []string{"Python license"},
								FilePath: "testdata/happy.dist-info/METADATA",
							},
						},
					},
				},
			},
		},
		{
			name:      "egg zip doesn't contain required files",
			inputFile: "testdata/no-required-files.egg",
			want:      nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			stat, err := f.Stat()
			require.NoError(t, err)

			a := packagingAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Info:     stat,
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

func Test_packagingAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "egg",
			filePath: "python2.7/site-packages/cssutils-1.0-py2.7.egg/EGG-INFO/PKG-INFO",
			want:     true,
		},
		{
			name:     "egg-info",
			filePath: "python3.8/site-packages/wrapt-1.12.1.egg-info",
			want:     true,
		},
		{
			name:     "egg-info PKG-INFO",
			filePath: "python3.8/site-packages/wrapt-1.12.1.egg-info/PKG-INFO",
			want:     true,
		},
		{
			name:     "wheel",
			filePath: "python3.8/site-packages/wrapt-1.12.1.dist-info/METADATA",
			want:     true,
		},
		{
			name:     "sad",
			filePath: "random/PKG-INFO",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := packagingAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

package meta

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
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "pip",
			inputFile: "testdata/pip-22.2.2-py38h06a4308_0.json",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.CondaPkg,
						FilePath: "testdata/pip-22.2.2-py38h06a4308_0.json",
						Libraries: types.Packages{
							{
								Name:     "pip",
								Version:  "22.2.2",
								Licenses: []string{"MIT"},
								FilePath: "testdata/pip-22.2.2-py38h06a4308_0.json",
							},
						},
					},
				},
			},
		},
		{
			name:      "invalid",
			inputFile: "testdata/invalid.json",
			wantErr:   "unable to parse conda package",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			stat, err := f.Stat()
			require.NoError(t, err)

			a := metaAnalyzer{}
			ctx := context.Background()
			got, err := a.Analyze(ctx, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Info:     stat,
				Content:  f,
			})

			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
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
			name:     "pip",
			filePath: "/home/<user>/miniconda3/envs/<env>/conda-meta/pip-22.2.2-py38h06a4308_0.json",
			want:     true,
		},
		{
			name:     "invalid",
			filePath: "/home/<user>/miniconda3/envs/<env>/conda-meta/invalid.json",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := metaAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

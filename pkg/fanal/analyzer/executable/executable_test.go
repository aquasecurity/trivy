package executable

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
)

func Test_executableAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     *analyzer.AnalysisResult
	}{
		{
			name:     "binary",
			filePath: "testdata/binary",
			want: &analyzer.AnalysisResult{
				Digests: map[string]string{
					"testdata/binary": "sha256:9f64a747e1b97f131fabb6b447296c9b6f0201e79fb3c5356e6c77e89b6a806a",
				},
			},
		},
		{
			name:     "text",
			filePath: "testdata/hello.txt",
			want:     nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.filePath)
			require.NoError(t, err)
			defer f.Close()

			stat, err := f.Stat()
			require.NoError(t, err)

			a := executableAnalyzer{}
			got, err := a.Analyze(context.Background(), analyzer.AnalysisInput{
				FilePath: tt.filePath,
				Content:  f,
				Info:     stat,
			})
			assert.Equal(t, tt.want, got)
		})
	}
}

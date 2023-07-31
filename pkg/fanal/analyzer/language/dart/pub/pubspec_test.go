package pub

import (
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"os"
	"sort"
	"testing"
)

func Test_pubSpecLockAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   assert.ErrorAssertionFunc
	}{
		{
			name:      "happy path",
			inputFile: "testdata/happy.lock",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.Pub,
						FilePath: "testdata/happy.lock",
						Libraries: types.Packages{
							{
								ID:      "crypto@3.0.2",
								Name:    "crypto",
								Version: "3.0.2",
							},
							{
								ID:      "flutter_test@0.0.0",
								Name:    "flutter_test",
								Version: "0.0.0",
							},
							{
								ID:       "uuid@3.0.6",
								Name:     "uuid",
								Version:  "3.0.6",
								Indirect: true,
							},
						},
					},
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:      "empty file",
			inputFile: "testdata/empty.lock",
			wantErr:   assert.NoError,
		},
		{
			name:      "broken file",
			inputFile: "testdata/broken.lock",
			wantErr:   assert.Error,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := pubSpecLockAnalyzer{}
			got, err := a.Analyze(nil, analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})

			if got != nil {
				for _, app := range got.Applications {
					sort.Sort(app.Libraries)
				}
			}

			if !tt.wantErr(t, err, tt.inputFile) {
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_pubSpecLockAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "happy path",
			filePath: "pubspec.lock",
			want:     true,
		},
		{
			name:     "sad path",
			filePath: "test.txt",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := pubSpecLockAnalyzer{}
			got := a.Required(tt.filePath, nil)
			assert.Equal(t, tt.want, got)
		})
	}
}

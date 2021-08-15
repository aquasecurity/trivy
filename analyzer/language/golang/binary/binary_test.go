package binary

import (
	"io/ioutil"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/types"
	godeptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
)

func Test_gobinaryLibraryAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
		wantErr   string
	}{
		{
			name:      "happy path",
			inputFile: "testdata/executable_gobinary",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.GoBinary,
						FilePath: "testdata/executable_gobinary",
						Libraries: []types.LibraryInfo{
							{Library: godeptypes.Library{Name: "github.com/aquasecurity/go-pep440-version", Version: "v0.0.0-20210121094942-22b2f8951d46"}},
							{Library: godeptypes.Library{Name: "github.com/aquasecurity/go-version", Version: "v0.0.0-20210121072130-637058cfe492"}},
							{Library: godeptypes.Library{Name: "golang.org/x/xerrors", Version: "v0.0.0-20200804184101-5ec99f83aff1"}},
						},
					},
				},
			},
		},
		{
			name:      "sad path not gobinary",
			inputFile: "testdata/executable_bash",
			wantErr:   "unrecognized executable format",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := ioutil.ReadFile(tt.inputFile)
			require.NoError(t, err)

			a := gobinaryLibraryAnalyzer{}
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

func Test_gobinaryLibraryAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     bool
	}{
		{
			name:     "file perm 0755",
			filePath: "testdata/0755",
			want:     true,
		},
		{
			name:     "file perm 0644",
			filePath: "testdata/0644",
			want:     false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := gobinaryLibraryAnalyzer{}
			fileInfo, err := os.Stat(tt.filePath)
			require.NoError(t, err)
			got := a.Required(tt.filePath, fileInfo)
			assert.Equal(t, tt.want, got, fileInfo.Mode().Perm())
		})
	}

}

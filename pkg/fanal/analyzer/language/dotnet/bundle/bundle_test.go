package bundle

import (
	"io/fs"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

const testdata = "../../../../../dependency/parser/dotnet/bundle/testdata/"

func Test_dotnetBundleAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name      string
		inputFile string
		want      *analyzer.AnalysisResult
	}{
		{
			name:      "single-file bundle",
			inputFile: testdata + "test.elf",
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.DotNetCore,
						FilePath: testdata + "test.elf",
						Packages: types.Packages{
							{
								ID:           "BundleApp/1.0.0",
								Name:         "BundleApp",
								Version:      "1.0.0",
								Relationship: types.RelationshipRoot,
								DependsOn:    []string{"Ardalis.GuardClauses/4.5.0"},
							},
							{
								ID:           "Ardalis.GuardClauses/4.5.0",
								Name:         "Ardalis.GuardClauses",
								Version:      "4.5.0",
								Relationship: types.RelationshipDirect,
							},
						},
					},
				},
			},
		},
		{
			name:      "apphost that is not a bundle",
			inputFile: testdata + "apphost.elf",
		},
		{
			name:      "not an executable",
			inputFile: testdata + "dummy",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.inputFile)
			require.NoError(t, err)
			defer f.Close()

			a := dotnetBundleAnalyzer{}
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				FilePath: tt.inputFile,
				Content:  f,
			})
			require.NoError(t, err)
			assert.Equal(t, tt.want, got)
		})
	}
}

type fakeFileInfo struct {
	name string
	mode fs.FileMode
}

func (f fakeFileInfo) Name() string       { return f.name }
func (f fakeFileInfo) Size() int64        { return 0 }
func (f fakeFileInfo) Mode() fs.FileMode  { return f.mode }
func (f fakeFileInfo) ModTime() time.Time { return time.Time{} }
func (f fakeFileInfo) IsDir() bool        { return false }
func (f fakeFileInfo) Sys() any           { return nil }

func Test_dotnetBundleAnalyzer_Required(t *testing.T) {
	tests := []struct {
		name string
		info fakeFileInfo
		want bool
	}{
		{
			name: "executable",
			info: fakeFileInfo{name: "app", mode: 0o755},
			want: true,
		},
		{
			name: "Windows executable without the executable bit",
			info: fakeFileInfo{name: "app.exe", mode: 0o644},
			want: true,
		},
		{
			name: "not executable",
			info: fakeFileInfo{name: "app.deps.json", mode: 0o644},
			want: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := dotnetBundleAnalyzer{}.Required(tt.info.name, tt.info)
			assert.Equal(t, tt.want, got)
		})
	}
}

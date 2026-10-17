package packaging

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func Test_zipAppAnalyzer_Analyze(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  *analyzer.AnalysisResult
	}{
		{
			name: "zipapp with installed packages",
			files: map[string]string{
				"__main__.py":                                    "print('hello')",
				"requests-2.32.4.dist-info/METADATA":             "Name: requests\nVersion: 2.32.4\n",
				"site-packages/urllib3-2.5.0.dist-info/METADATA": "Name: urllib3\nVersion: 2.5.0\n",
			},
			want: &analyzer.AnalysisResult{
				Applications: []types.Application{
					{
						Type:     types.PythonPkg,
						FilePath: "app.pyz",
						Packages: types.Packages{
							{
								Name:     "requests",
								Version:  "2.32.4",
								FilePath: "app.pyz/requests-2.32.4.dist-info/METADATA",
							},
							{
								Name:     "urllib3",
								Version:  "2.5.0",
								FilePath: "app.pyz/site-packages/urllib3-2.5.0.dist-info/METADATA",
							},
						},
					},
				},
			},
		},
		{
			name: "archive without root main",
			files: map[string]string{
				"example-1.0.0.dist-info/METADATA": "Name: example\nVersion: 1.0.0\n",
			},
			want: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			contents := newZipApp(t, tt.files)
			info, err := fs.Stat(fstest.MapFS{
				"app.pyz": {Data: contents},
			}, "app.pyz")
			require.NoError(t, err)

			a := &zipAppAnalyzer{}
			require.NoError(t, a.Init(analyzer.AnalyzerOptions{}))
			got, err := a.Analyze(t.Context(), analyzer.AnalysisInput{
				Content:  bytes.NewReader(contents),
				FilePath: "app.pyz",
				Info:     info,
			})

			require.NoError(t, err)
			if got != nil && tt.want != nil {
				assert.Equal(t, tt.want.Applications[0].Type, got.Applications[0].Type)
				assert.Equal(t, tt.want.Applications[0].FilePath, got.Applications[0].FilePath)
				assert.ElementsMatch(t, tt.want.Applications[0].Packages, got.Applications[0].Packages)
				return
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func Test_zipAppAnalyzer_Required(t *testing.T) {
	tests := []struct {
		filePath string
		want     bool
	}{
		{filePath: "app.pyz", want: true},
		{filePath: "app.PYZW", want: true},
		{filePath: "app.zip", want: false},
	}

	a := &zipAppAnalyzer{}
	for _, tt := range tests {
		t.Run(tt.filePath, func(t *testing.T) {
			assert.Equal(t, tt.want, a.Required(tt.filePath, nil))
		})
	}
}

func newZipApp(t *testing.T, files map[string]string) []byte {
	t.Helper()

	var buf bytes.Buffer
	buf.WriteString("#!/usr/bin/env python3\n")
	zw := zip.NewWriter(&buf)
	for name, contents := range files {
		f, err := zw.Create(name)
		require.NoError(t, err)
		_, err = f.Write([]byte(contents))
		require.NoError(t, err)
	}
	require.NoError(t, zw.Close())
	return buf.Bytes()
}

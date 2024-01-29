package walker_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestLayerTar_Walk(t *testing.T) {
	type fields struct {
		skipFiles []string
		skipDirs  []string
		onlyDirs  []string
	}
	tests := []struct {
		name        string
		fields      fields
		inputFile   string
		analyzeFn   walker.WalkFunc
		wantOpqDirs []string
		wantWhFiles []string
		wantErr     string
	}{
		{
			name:      "happy path",
			inputFile: filepath.Join("testdata", "test.tar"),
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				return nil
			},
			wantOpqDirs: []string{"etc/"},
			wantWhFiles: []string{"foo/foo"},
		},
		{
			name:      "skip file",
			inputFile: filepath.Join("testdata", "test.tar"),
			fields: fields{
				skipFiles: []string{"/app/myweb/index.html"},
			},
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				if filePath == "app/myweb/index.html" {
					assert.Fail(t, "skip files error", "%s should be skipped", filePath)
				}
				return nil
			},
			wantOpqDirs: []string{"etc/"},
			wantWhFiles: []string{"foo/foo"},
		},
		{
			name:      "skip dir",
			inputFile: filepath.Join("testdata", "test.tar"),
			fields: fields{
				skipDirs: []string{"/app"},
			},
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				if strings.HasPrefix(filePath, "app") {
					assert.Fail(t, "skip dirs error", "%s should be skipped", filePath)
				}
				return nil
			},
			wantOpqDirs: []string{"etc/"},
			wantWhFiles: []string{"foo/foo"},
		},
		{
			name:      "sad path",
			inputFile: "testdata/test.tar",
			analyzeFn: func(filePath string, info os.FileInfo, opener analyzer.Opener) error {
				return errors.New("error")
			},
			wantErr: "failed to analyze file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open("testdata/test.tar")
			require.NoError(t, err)

			w := walker.NewLayerTar(tt.fields.skipFiles, tt.fields.skipDirs, tt.fields.onlyDirs)

			gotOpqDirs, gotWhFiles, err := w.Walk(f, tt.analyzeFn)
			if tt.wantErr != "" {
				require.Error(t, err)
				assert.Contains(t, err.Error(), tt.wantErr)
				return
			}
			assert.NoError(t, err)
			assert.Equal(t, tt.wantOpqDirs, gotOpqDirs)
			assert.Equal(t, tt.wantWhFiles, gotWhFiles)
		})
	}
}

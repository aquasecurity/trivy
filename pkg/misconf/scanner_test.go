package misconf

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/config"
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

func TestScanner_Scan(t *testing.T) {
	tests := []struct {
		name         string
		files        []types.File
		filePatterns []string
		wantFilePath string
		wantFileType string
	}{
		{
			name: "happy path. Dockerfile",
			files: []types.File{
				{
					Path:    "Dockerfile",
					Type:    types.Dockerfile,
					Content: []byte(`FROM alpine`),
				},
			},
			wantFilePath: "Dockerfile",
			wantFileType: types.Dockerfile,
		},
		{
			name: "happy path. Dockerfile with custom file name",
			files: []types.File{
				{
					Path:    "dockerf",
					Type:    types.Dockerfile,
					Content: []byte(`FROM alpine`),
				},
			},
			filePatterns: []string{"dockerfile:dockerf"},
			wantFilePath: "dockerf",
			wantFileType: types.Dockerfile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s, err := NewScanner(tt.filePatterns, config.ScannerOption{})
			require.NoError(t, err)

			misconfs, err := s.Scan(context.Background(), tt.files)
			require.NoError(t, err)
			assert.Equal(t, 1, len(misconfs), "wrong number of misconfigurations found")
			assert.Equal(t, tt.wantFilePath, misconfs[0].FilePath, "filePaths don't equal")
			assert.Equal(t, tt.wantFileType, misconfs[0].FileType, "fileTypes don't equal")
		})
	}
}

func Test_createPolicyFS(t *testing.T) {
	t.Run("outside pwd", func(t *testing.T) {
		tmpDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(tmpDir, "subdir/testdir"), 0750))
		f, got, err := createPolicyFS([]string{filepath.Join(tmpDir, "subdir/testdir")})
		require.NoError(t, err)
		assert.Equal(t, []string{"."}, got)

		d, err := f.Open(tmpDir)
		require.NoError(t, err)
		stat, err := d.Stat()
		require.NoError(t, err)
		assert.True(t, stat.IsDir())
	})
}

package misconf

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/mapfs"
)

func TestScannerOption_Sort(t *testing.T) {
	type fields struct {
		Namespaces  []string
		PolicyPaths []string
		DataPaths   []string
	}
	tests := []struct {
		name   string
		fields fields
		want   ScannerOption
	}{
		{
			name: "happy path",
			fields: fields{
				Namespaces:  []string{"main", "custom", "default"},
				PolicyPaths: []string{"policy"},
				DataPaths:   []string{"data/b", "data/c", "data/a"},
			},
			want: ScannerOption{
				Namespaces:  []string{"custom", "default", "main"},
				PolicyPaths: []string{"policy"},
				DataPaths:   []string{"data/a", "data/b", "data/c"},
			},
		},
		{
			name: "missing some fields",
			fields: fields{
				Namespaces:  []string{"main"},
				PolicyPaths: nil,
				DataPaths:   nil,
			},
			want: ScannerOption{
				Namespaces: []string{"main"},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := ScannerOption{
				Namespaces:  tt.fields.Namespaces,
				PolicyPaths: tt.fields.PolicyPaths,
				DataPaths:   tt.fields.DataPaths,
			}
			o.Sort()

			assert.Equal(t, tt.want, o)
		})
	}
}

func TestScanner_Scan(t *testing.T) {
	type fields struct {
		filePatterns []string
		opt          ScannerOption
	}
	type file struct {
		path    string
		content []byte
	}
	tests := []struct {
		name         string
		fields       fields
		files        []file
		wantFilePath string
		wantFileType string
	}{
		{
			name: "happy path. Dockerfile",
			fields: fields{
				opt: ScannerOption{},
			},
			files: []file{
				{
					path:    "Dockerfile",
					content: []byte(`FROM alpine`),
				},
			},
			wantFilePath: "Dockerfile",
			wantFileType: types.Dockerfile,
		},
		{
			name: "happy path. Dockerfile with custom file name",
			fields: fields{
				filePatterns: []string{"dockerfile:dockerf"},
				opt:          ScannerOption{},
			},
			files: []file{
				{
					path:    "dockerf",
					content: []byte(`FROM alpine`),
				},
			},
			wantFilePath: "dockerf",
			wantFileType: types.Dockerfile,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create a virtual filesystem for testing
			fsys := mapfs.New()
			for _, f := range tt.files {
				err := fsys.WriteVirtualFile(f.path, f.content, 0666)
				require.NoError(t, err)
			}

			s, err := NewDockerfileScanner(tt.fields.filePatterns, tt.fields.opt)
			require.NoError(t, err)

			misconfs, err := s.Scan(context.Background(), fsys)
			require.NoError(t, err)
			require.Equal(t, 1, len(misconfs), "wrong number of misconfigurations found")
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

package snapshot

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadSnapshot(t *testing.T) {
	tests := []struct {
		name          string
		dir           string
		expectedFiles []string
	}{
		{
			name:          "just resource",
			dir:           "just-resource",
			expectedFiles: []string{"main.tf", "terraform.tf"},
		},
		{
			name:          "with local module",
			dir:           "with-local-module",
			expectedFiles: []string{"main.tf", "modules/ec2/main.tf", "terraform.tf"},
		},
		{
			name: "with nested modules",
			dir:  "nested-modules",
			expectedFiles: []string{
				"main.tf",
				"modules/s3/main.tf",
				"modules/s3/modules/logging/main.tf",
				"terraform.tf",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(filepath.Join("testdata", tt.dir, "tfplan"))
			require.NoError(t, err)
			defer f.Close()

			snapshot, err := parseSnapshot(f)
			require.NoError(t, err)
			require.NotNil(t, snapshot)

			fsys, err := snapshot.toFS()
			require.NoError(t, err)

			files, err := getAllfiles(fsys)
			require.NoError(t, err)

			assert.Equal(t, tt.expectedFiles, files)
		})
	}
}

func getAllfiles(fsys fs.FS) ([]string, error) {
	var files []string
	walkFn := func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if d.IsDir() {
			return nil
		}

		files = append(files, filepath.ToSlash(path))
		return nil
	}
	if err := fs.WalkDir(fsys, ".", walkFn); err != nil {
		return nil, err
	}

	sort.Strings(files)
	return files, nil
}

func TestIsPlanSnapshot(t *testing.T) {
	t.Run("TF plan", func(t *testing.T) {
		f, err := os.Open(filepath.Join("testdata", "just-resource", "tfplan"))
		require.NoError(t, err)
		defer f.Close()

		got := IsPlanSnapshot(f)
		assert.True(t, got)
	})

	t.Run("just a zip file", func(t *testing.T) {
		var b bytes.Buffer
		zw := zip.NewWriter(&b)
		defer zw.Close()

		w, err := zw.Create("test.txt")
		require.NoError(t, err)

		w.Write([]byte("test"))

		got := IsPlanSnapshot(&b)
		assert.False(t, got)
	})
}

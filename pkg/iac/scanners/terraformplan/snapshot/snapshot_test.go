package snapshot

import (
	"archive/zip"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/zclconf/go-cty/cty"
)

func TestReadSnapshot(t *testing.T) {
	tests := []struct {
		name          string
		dir           string
		expectedFiles []string
	}{
		{
			name: "just resource",
			dir:  "just-resource",
			expectedFiles: []string{
				"main.tf",
				"terraform.tf",
				".terraform/modules/modules.json",
			},
		},
		{
			name: "with local module",
			dir:  "with-local-module",
			expectedFiles: []string{
				"main.tf",
				"terraform.tf",
				"modules/ec2/main.tf",
				".terraform/modules/modules.json",
			},
		},
		{
			name: "with nested modules",
			dir:  "nested-modules",
			expectedFiles: []string{
				"main.tf",
				"terraform.tf",
				"modules/s3/main.tf",
				"modules/s3/modules/logging/main.tf",
				".terraform/modules/modules.json",
			},
		},
		{
			name: "with remote module",
			dir:  "with-remote-module",
			expectedFiles: []string{
				"main.tf",
				"terraform.tf",
				".terraform/modules/modules.json",
				".terraform/modules/s3_bucket/main.tf",
				".terraform/modules/s3_bucket/outputs.tf",
				".terraform/modules/s3_bucket/variables.tf",
				".terraform/modules/s3_bucket/versions.tf",
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

			assert.ElementsMatch(t, tt.expectedFiles, files)
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

func TestPlanWithVariables(t *testing.T) {
	f, err := os.Open(filepath.Join("testdata", "with-var", "tfplan"))
	require.NoError(t, err)
	defer f.Close()

	snapshot, err := parseSnapshot(f)
	require.NoError(t, err)
	require.NotNil(t, snapshot)

	expectedVars := map[string]cty.Value{
		"bucket_name": cty.StringVal("test-bucket"),
	}
	assert.Equal(t, expectedVars, snapshot.inputVariables)
}

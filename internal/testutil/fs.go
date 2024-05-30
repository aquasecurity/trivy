package testutil

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/utils/fsutils"
)

// CopyDir copies the directory content from src to dst.
// It supports only simple cases for testing.
func CopyDir(t *testing.T, src, dst string) {
	srcInfo, err := os.Stat(src)
	require.NoError(t, err)

	err = os.MkdirAll(dst, srcInfo.Mode())
	require.NoError(t, err)

	entries, err := os.ReadDir(src)
	require.NoError(t, err)

	for _, entry := range entries {
		srcPath := filepath.Join(src, entry.Name())
		dstPath := filepath.Join(dst, entry.Name())

		if entry.IsDir() {
			CopyDir(t, srcPath, dstPath)
		} else {
			_, err = fsutils.CopyFile(srcPath, dstPath)
			require.NoError(t, err)
		}
	}
}

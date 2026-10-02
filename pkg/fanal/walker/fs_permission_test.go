package walker_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestFS_WalkUnreadable(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("file mode permissions do not deny reads on Windows")
	}
	if os.Geteuid() == 0 {
		t.Skip("root bypasses the permission check")
	}

	t.Run("unreadable root fails the walk", func(t *testing.T) {
		root := t.TempDir()
		require.NoError(t, os.WriteFile(filepath.Join(root, "go.mod"), []byte("module x\n"), 0o644))
		require.NoError(t, os.Chmod(root, 0o000))
		t.Cleanup(func() { _ = os.Chmod(root, 0o755) })

		var visited []string
		err := walker.NewFS().Walk(root, walker.Option{}, func(p string, _ os.FileInfo, _ analyzer.Opener) error {
			visited = append(visited, p)
			return nil
		})

		// Nothing could be read, so the walk must report that rather than look
		// like a scan that found nothing.
		assert.ErrorContains(t, err, "unable to read")
		assert.Empty(t, visited)
	})

	t.Run("unreadable directory below the root is skipped", func(t *testing.T) {
		root := t.TempDir()
		for _, dir := range []string{"good", "bad"} {
			path := filepath.Join(root, dir)
			require.NoError(t, os.MkdirAll(path, 0o755))
			require.NoError(t, os.WriteFile(filepath.Join(path, "go.mod"), []byte("module x\n"), 0o644))
		}
		require.NoError(t, os.Chmod(filepath.Join(root, "bad"), 0o000))
		t.Cleanup(func() { _ = os.Chmod(filepath.Join(root, "bad"), 0o755) })

		var visited []string
		err := walker.NewFS().Walk(root, walker.Option{}, func(p string, _ os.FileInfo, _ analyzer.Opener) error {
			visited = append(visited, p)
			return nil
		})

		// The readable part of the tree is still scanned, which is the existing
		// behaviour and the reason permission errors are ignored at all.
		require.NoError(t, err)
		assert.Equal(t, []string{"good/go.mod"}, visited)
	})
}

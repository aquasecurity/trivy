package walker_test

import (
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/walker"
)

func TestFS_Walk(t *testing.T) {
	tests := []struct {
		name      string
		option    walker.Option
		rootDir   string
		analyzeFn walker.WalkFunc
		wantErr   string
	}{
		{
			name:    "happy path",
			rootDir: "testdata/fs",
			analyzeFn: func(filePath string, _ os.FileInfo, opener analyzer.Opener) error {
				if filePath == "testdata/fs/bar" {
					got, err := opener()
					require.NoError(t, err)

					b, err := io.ReadAll(got)
					require.NoError(t, err)

					assert.Equal(t, "bar", string(b))
				}
				return nil
			},
		},
		{
			name:    "skip file",
			rootDir: "testdata/fs",
			option: walker.Option{
				SkipFiles: []string{"testdata/fs/bar"},
			},
			analyzeFn: func(filePath string, _ os.FileInfo, _ analyzer.Opener) error {
				if filePath == "testdata/fs/bar" {
					assert.Fail(t, "skip files error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "skip dir",
			rootDir: "testdata/fs/",
			option: walker.Option{
				SkipDirs: []string{"/testdata/fs/app"},
			},
			analyzeFn: func(filePath string, _ os.FileInfo, _ analyzer.Opener) error {
				if strings.HasPrefix(filePath, "testdata/fs/app") {
					assert.Fail(t, "skip dirs error", "%s should be skipped", filePath)
				}
				return nil
			},
		},
		{
			name:    "sad path",
			rootDir: "testdata/fs",
			analyzeFn: func(string, os.FileInfo, analyzer.Opener) error {
				return errors.New("error")
			},
			wantErr: "failed to analyze file",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := walker.NewFS()
			err := w.Walk(tt.rootDir, tt.option, tt.analyzeFn)
			if tt.wantErr != "" {
				assert.ErrorContains(t, err, tt.wantErr)
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestFS_Walk_FollowSymlinks(t *testing.T) {
	// testdata/fs/sym.txt is a symlink to the regular file testdata/fs/bar.
	tests := []struct {
		name           string
		followSymlinks bool
		wantVisited    bool
	}{
		{
			name:           "disabled (default): symlink skipped",
			followSymlinks: false,
			wantVisited:    false,
		},
		{
			name:           "enabled: symlink to regular file followed",
			followSymlinks: true,
			wantVisited:    true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var visited []string
			var symContent string
			err := walker.NewFS().Walk("testdata/fs", walker.Option{FollowSymlinks: tt.followSymlinks},
				func(filePath string, _ os.FileInfo, opener analyzer.Opener) error {
					visited = append(visited, filePath)
					if filePath == "sym.txt" {
						r, err := opener()
						require.NoError(t, err)
						b, err := io.ReadAll(r)
						require.NoError(t, err)
						symContent = string(b)
					}
					return nil
				})
			require.NoError(t, err)

			// The walker yields paths relative to the scan root, so the
			// symlink appears as "sym.txt", not "testdata/fs/sym.txt".
			assert.Contains(t, visited, "bar", "regular files must always be walked")
			gotVisited := slices.Contains(visited, "sym.txt")
			assert.Equal(t, tt.wantVisited, gotVisited)
			if tt.wantVisited {
				assert.Equal(t, "bar", symContent, "symlink should resolve to its target's content")
			}
		})
	}
}

func TestFS_Walk_FollowSymlinks_SkipsDirsAndBrokenLinks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation requires privileges on Windows")
	}
	// A tree exercising the three symlink target kinds the walker handles.
	root := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(root, "real.txt"), []byte("real"), 0o644))
	require.NoError(t, os.Mkdir(filepath.Join(root, "subdir"), 0o755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "subdir", "nested.txt"), []byte("nested"), 0o644))
	require.NoError(t, os.Symlink(filepath.Join(root, "real.txt"), filepath.Join(root, "file-link")))  // -> regular file
	require.NoError(t, os.Symlink(filepath.Join(root, "subdir"), filepath.Join(root, "dir-link")))     // -> directory
	require.NoError(t, os.Symlink(filepath.Join(root, "missing"), filepath.Join(root, "broken-link"))) // -> nonexistent

	var visited []string
	err := walker.NewFS().Walk(root, walker.Option{FollowSymlinks: true},
		func(filePath string, _ os.FileInfo, _ analyzer.Opener) error {
			visited = append(visited, filePath)
			return nil
		})
	require.NoError(t, err) // a broken symlink must not abort the walk

	assert.Contains(t, visited, "real.txt", "regular files are always walked")
	assert.Contains(t, visited, "subdir/nested.txt", "real subdirectories are walked")
	assert.Contains(t, visited, "file-link", "symlink to a regular file is followed")
	assert.NotContains(t, visited, "dir-link", "symlink to a directory is not followed")
	assert.NotContains(t, visited, "broken-link", "broken symlink is skipped")
	for _, p := range visited {
		assert.False(t, strings.HasPrefix(p, "dir-link/"), "must not traverse into a directory symlink: %s", p)
	}
}

func TestFS_BuildSkipPaths(t *testing.T) {
	tests := []struct {
		name  string
		oses  []string
		paths []string
		base  string
		want  []string
	}{
		// Linux/macOS
		{
			name: "path - abs, base - abs, not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "/foo",
			paths: []string{"/foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - abs, base - rel",
			oses: []string{
				"linux",
				"darwin",
			},
			base: "foo",
			paths: func() []string {
				abs, err := filepath.Abs("foo/bar")
				require.NoError(t, err)
				return []string{abs}
			}(),
			want: []string{"bar"},
		},
		{
			name: "path - rel, base - rel, joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - rel, base - rel, not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"foo/bar/bar"},
			want:  []string{"bar/bar"},
		},
		{
			name: "path - rel with dot, base - rel, removing the leading dot and not joining paths",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  "foo",
			paths: []string{"./foo/bar"},
			want:  []string{"bar"},
		},
		{
			name: "path - rel, base - dot",
			oses: []string{
				"linux",
				"darwin",
			},
			base:  ".",
			paths: []string{"foo/bar"},
			want:  []string{"foo/bar"},
		},
		// Windows
		{
			name:  "path - rel, base - rel. Skip common prefix",
			oses:  []string{"windows"},
			base:  "foo",
			paths: []string{"foo\\bar\\bar"},
			want:  []string{"bar/bar"},
		},
		{
			name:  "path - rel, base - dot, windows",
			oses:  []string{"windows"},
			base:  ".",
			paths: []string{"foo\\bar"},
			want:  []string{"foo/bar"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if !slices.Contains(tt.oses, runtime.GOOS) {
				t.Skipf("Skip path tests for %q", tt.oses)
			}
			got := walker.NewFS().BuildSkipPaths(tt.base, tt.paths)
			assert.Equal(t, tt.want, got)
		})
	}
}

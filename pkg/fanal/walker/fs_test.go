package walker_test

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"syscall"
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

// fakeDirEntry is a fs.DirEntry that fails on Info().
type fakeDirEntry struct {
	infoErr error
}

func (e fakeDirEntry) Name() string               { return "bad" }
func (e fakeDirEntry) IsDir() bool                { return false }
func (e fakeDirEntry) Type() fs.FileMode          { return 0 } // regular file
func (e fakeDirEntry) Info() (fs.FileInfo, error) { return nil, e.infoErr }

func TestFS_WalkDirFunc_UnreadablePaths(t *testing.T) {
	root := "testdata/fs"
	analyzeFn := func(string, os.FileInfo, analyzer.Opener) error {
		assert.Fail(t, "analyze function must not be called for unreadable paths")
		return nil
	}
	walkFn := walker.NewFS().WalkDirFunc(root, analyzeFn, walker.Option{})

	t.Run("unreadable file is skipped", func(t *testing.T) {
		// e.g. "lstat: input/output error" on a broken filesystem
		// cf. https://github.com/aquasecurity/trivy/issues/3259
		err := walkFn(filepath.Join(root, "bad"), nil, &fs.PathError{
			Op:   "lstat",
			Path: filepath.Join(root, "bad"),
			Err:  syscall.EIO,
		})
		assert.NoError(t, err)
	})

	t.Run("error with the root is returned", func(t *testing.T) {
		err := walkFn(root, nil, &fs.PathError{
			Op:   "lstat",
			Path: root,
			Err:  syscall.EIO,
		})
		assert.ErrorIs(t, err, syscall.EIO)
	})

	t.Run("file with unreadable info is skipped", func(t *testing.T) {
		err := walkFn(filepath.Join(root, "bad"), fakeDirEntry{infoErr: syscall.EIO}, nil)
		assert.NoError(t, err)
	})
}

func TestFS_Walk_NonExistentRoot(t *testing.T) {
	analyzeFn := func(string, os.FileInfo, analyzer.Opener) error {
		return nil
	}
	err := walker.NewFS().Walk("testdata/non-existent", walker.Option{}, analyzeFn)
	assert.ErrorContains(t, err, "unknown error with")
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

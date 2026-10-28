package fsutils

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFile(t *testing.T) {
	type args struct {
		src string
		dst string
	}
	tests := []struct {
		name    string
		args    args
		content []byte
		want    string
		wantErr string
	}{
		{
			name:    "happy path",
			content: []byte("this is a content"),
			args:    args{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := tt.args.src
			if tt.args.src == "" {
				s, err := os.CreateTemp(t.TempDir(), "src")
				require.NoError(t, err, tt.name)
				_, err = s.Write(tt.content)
				require.NoError(t, err, tt.name)
				src = s.Name()
				require.NoError(t, s.Close())
			}

			dst := tt.args.dst
			if tt.args.dst == "" {
				d, err := os.CreateTemp(t.TempDir(), "dst")
				require.NoError(t, err, tt.name)
				dst = d.Name()
				require.NoError(t, d.Close(), tt.name)
			}

			_, err := CopyFile(src, dst)
			if tt.wantErr != "" {
				require.Error(t, err, tt.name)
				assert.Equal(t, tt.wantErr, err.Error(), tt.name)
			} else {
				require.NoError(t, err, tt.name)
			}
		})
	}
}

func TestDirExists(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		assert.False(t, DirExists("\000invalid:path"))
	})

	t.Run("valid path", func(t *testing.T) {
		assert.True(t, DirExists(t.TempDir()))
	})

	t.Run("dir not exist", func(t *testing.T) {
		assert.False(t, DirExists(filepath.Join(t.TempDir(), "tmp")))
	})

	t.Run("file path", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "tmp")
		f, err := os.Create(filePath)
		require.NoError(t, f.Close())
		require.NoError(t, err)
		assert.False(t, DirExists(filePath))
	})
}

func TestFileExists(t *testing.T) {
	t.Run("invalid path", func(t *testing.T) {
		assert.False(t, FileExists("\000invalid:path"))
	})

	t.Run("valid path", func(t *testing.T) {
		filePath := filepath.Join(t.TempDir(), "tmp")
		f, err := os.Create(filePath)
		require.NoError(t, f.Close())
		require.NoError(t, err)
		assert.True(t, FileExists(filePath))
	})

	t.Run("file not exist", func(t *testing.T) {
		assert.False(t, FileExists(filepath.Join(t.TempDir(), "tmp")))
	})

	t.Run("dir path", func(t *testing.T) {
		assert.False(t, FileExists(t.TempDir()))
	})
}

func TestHomeDir(t *testing.T) {
	t.Run("XDG_DATA_HOME is set", func(t *testing.T) {
		dir := t.TempDir()
		t.Setenv(xdgDataHome, dir)
		assert.Equal(t, dir, HomeDir())
	})

	t.Run("XDG_DATA_HOME is empty, falls back to user home dir", func(t *testing.T) {
		home := t.TempDir()
		t.Setenv(xdgDataHome, "")
		t.Setenv("HOME", home)        // Linux/macOS
		t.Setenv("USERPROFILE", home) // Windows
		assert.Equal(t, home, HomeDir())
	})
}

func TestTrivyHomeDir(t *testing.T) {
	dir := t.TempDir()
	t.Setenv(xdgDataHome, dir)
	assert.Equal(t, filepath.Join(dir, ".trivy"), TrivyHomeDir())
}

func TestCopyFile_Content(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src.txt")
	dst := filepath.Join(dir, "dst.txt")
	content := []byte("this is a content")
	require.NoError(t, os.WriteFile(src, content, 0o600))

	n, err := CopyFile(src, dst)
	require.NoError(t, err)
	assert.Equal(t, int64(len(content)), n)

	got, err := os.ReadFile(dst)
	require.NoError(t, err)
	assert.Equal(t, content, got)
}

func TestCopyFile_Errors(t *testing.T) {
	t.Run("source does not exist", func(t *testing.T) {
		dir := t.TempDir()
		n, err := CopyFile(filepath.Join(dir, "missing"), filepath.Join(dir, "dst"))
		require.ErrorContains(t, err, "stat error")
		assert.Zero(t, n)
	})

	t.Run("source is a directory", func(t *testing.T) {
		dir := t.TempDir()
		n, err := CopyFile(dir, filepath.Join(t.TempDir(), "dst"))
		require.ErrorContains(t, err, "is not a regular file")
		assert.Zero(t, n)
	})

	t.Run("destination cannot be created", func(t *testing.T) {
		dir := t.TempDir()
		src := filepath.Join(dir, "src.txt")
		require.NoError(t, os.WriteFile(src, []byte("data"), 0o600))

		dst := filepath.Join(dir, "missing-dir", "dst.txt")
		n, err := CopyFile(src, dst)
		require.Error(t, err)
		assert.Zero(t, n)
	})
}

func TestRequiredExt(t *testing.T) {
	tests := []struct {
		name string
		exts []string
		path string
		want bool
	}{
		{name: "matching extension", exts: []string{".txt"}, path: "dir/a.txt", want: true},
		{name: "non-matching extension", exts: []string{".txt"}, path: "dir/a.log", want: false},
		{name: "one of multiple extensions", exts: []string{".json", ".yaml"}, path: "b.yaml", want: true},
		{name: "no extensions given", exts: nil, path: "a.txt", want: false},
		{name: "file without extension", exts: []string{".txt"}, path: "Makefile", want: false},
		{name: "extension match is case sensitive", exts: []string{".txt"}, path: "A.TXT", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			required := RequiredExt(tt.exts...)
			assert.Equal(t, tt.want, required(tt.path, nil))
		})
	}
}

// openErrFS fails to open a single named file.
type openErrFS struct {
	fs.FS
	failOn string
}

func (f openErrFS) Open(name string) (fs.File, error) {
	if name == f.failOn {
		return nil, errors.New("open failed")
	}
	return f.FS.Open(name)
}

func TestWalkDir(t *testing.T) {
	fsys := fstest.MapFS{
		"a.txt":     {Data: []byte("a")},
		"dir/b.txt": {Data: []byte("b")},
		"dir/c.log": {Data: []byte("c")},
	}

	t.Run("only required files reach the callback", func(t *testing.T) {
		got := map[string]string{}
		err := WalkDir(fsys, ".", RequiredExt(".txt"), func(path string, _ fs.DirEntry, r io.Reader) error {
			b, err := io.ReadAll(r)
			require.NoError(t, err)
			got[path] = string(b)
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"a.txt": "a", "dir/b.txt": "b"}, got)
	})

	t.Run("callback error does not stop the walk", func(t *testing.T) {
		var visited []string
		all := func(string, fs.DirEntry) bool { return true }
		err := WalkDir(fsys, ".", all, func(path string, _ fs.DirEntry, _ io.Reader) error {
			visited = append(visited, path)
			return errors.New("callback failed")
		})
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"a.txt", "dir/b.txt", "dir/c.log"}, visited)
	})

	t.Run("file open error is returned", func(t *testing.T) {
		all := func(string, fs.DirEntry) bool { return true }
		err := WalkDir(openErrFS{FS: fsys, failOn: "a.txt"}, ".", all,
			func(string, fs.DirEntry, io.Reader) error { return nil })
		require.ErrorContains(t, err, "file open error")
	})

	t.Run("root does not exist", func(t *testing.T) {
		err := WalkDir(fsys, "no-such-dir", RequiredExt(".txt"),
			func(string, fs.DirEntry, io.Reader) error { return nil })
		require.Error(t, err)
	})
}

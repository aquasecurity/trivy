package mapfs_test

import (
	"io"
	"io/fs"
	"runtime"
	"testing"

	"github.com/samber/lo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/pkg/mapfs"
)

type fileInfo struct {
	name     string
	fileMode fs.FileMode
	isDir    bool
	size     int64
}

var (
	filePerm      = lo.Ternary(runtime.GOOS == "windows", fs.FileMode(0666), fs.FileMode(0644))
	helloFileInfo = fileInfo{
		name:     "hello.txt",
		fileMode: filePerm,
		isDir:    false,
		size:     11,
	}
	btxtFileInfo = fileInfo{
		name:     "b.txt",
		fileMode: filePerm,
		isDir:    false,
		size:     3,
	}
	virtualFileInfo = fileInfo{
		name:     "virtual.txt",
		fileMode: 0600,
		isDir:    false,
		size:     7,
	}
	cdirFileInfo = fileInfo{
		name:     "c",
		fileMode: fs.FileMode(0700) | fs.ModeDir,
		isDir:    true,
		size:     256,
	}
)

func initFS(t *testing.T) *mapfs.FS {
	fsys := mapfs.New()
	require.NoError(t, fsys.MkdirAll("a/b/c", 0700))
	require.NoError(t, fsys.MkdirAll("a/b/empty", 0700))
	require.NoError(t, fsys.WriteFile("hello.txt", "testdata/hello.txt"))
	require.NoError(t, fsys.WriteFile("a/b/b.txt", "testdata/b.txt"))
	require.NoError(t, fsys.WriteFile("a/b/c/c.txt", "testdata/c.txt"))
	require.NoError(t, fsys.WriteFile("a/b/c/.dotfile", "testdata/dotfile"))
	require.NoError(t, fsys.WriteVirtualFile("a/b/c/virtual.txt", []byte("virtual"), 0600))
	return fsys
}

func assertFileInfo(t *testing.T, want fileInfo, got fs.FileInfo) {
	if got == nil {
		return
	}
	assert.Equal(t, want.name, got.Name())
	assert.Equal(t, want.fileMode, got.Mode())
	assert.Equal(t, want.isDir, got.Mode().IsDir())
	assert.Equal(t, want.isDir, got.IsDir())
	assert.Equal(t, want.size, got.Size())
}

func TestFS_Filter(t *testing.T) {
	fsys := initFS(t)
	t.Run("empty files", func(t *testing.T) {
		newFS, err := fsys.Filter(nil)
		require.NoError(t, err)
		assert.Equal(t, fsys, newFS)
	})
	t.Run("happy", func(t *testing.T) {
		newFS, err := fsys.Filter([]string{
			"hello.txt",
			"a/b/c/.dotfile",
		})
		require.NoError(t, err)
		_, err = newFS.Stat("hello.txt")
		require.ErrorIs(t, err, fs.ErrNotExist)
		_, err = newFS.Stat("a/b/c/.dotfile")
		require.ErrorIs(t, err, fs.ErrNotExist)
		fi, err := newFS.Stat("a/b/c/c.txt")
		require.NoError(t, err)
		assert.Equal(t, "c.txt", fi.Name())
	})
}

func TestFS_Stat(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     fileInfo
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "ordinary file",
			filePath: "hello.txt",
			want:     helloFileInfo,
			wantErr:  assert.NoError,
		},
		{
			name:     "nested file",
			filePath: "a/b/b.txt",
			want:     btxtFileInfo,
			wantErr:  assert.NoError,
		},
		{
			name:     "virtual file",
			filePath: "a/b/c/virtual.txt",
			want:     virtualFileInfo,
			wantErr:  assert.NoError,
		},
		{
			name:     "dir",
			filePath: "a/b/c",
			want:     cdirFileInfo,
			wantErr:  assert.NoError,
		},
		{
			name:     "no such file",
			filePath: "nosuch.txt",
			wantErr:  assert.Error,
		},
	}

	for _, tt := range tests {
		fsys := initFS(t)
		t.Run(tt.name, func(t *testing.T) {
			got, err := fsys.Stat(tt.filePath)
			tt.wantErr(t, err)
			assertFileInfo(t, tt.want, got)
		})
	}
}

func TestFS_ReadDir(t *testing.T) {
	type dirEntry struct {
		name     string
		fileMode fs.FileMode
		isDir    bool
		size     int64
		fileInfo fileInfo
	}

	tests := []struct {
		name     string
		filePath string
		want     []dirEntry
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "at root",
			filePath: ".",
			want: []dirEntry{
				{
					name:     "a",
					fileMode: fs.FileMode(0700) | fs.ModeDir,
					isDir:    true,
					size:     0x100,
					fileInfo: fileInfo{
						name:     "a",
						fileMode: fs.FileMode(0700) | fs.ModeDir,
						isDir:    true,
						size:     0x100,
					},
				},
				{
					name:     "hello.txt",
					fileMode: filePerm,
					isDir:    false,
					size:     11,
					fileInfo: helloFileInfo,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:     "multiple files",
			filePath: "a/b/c",
			want: []dirEntry{
				{
					name:     ".dotfile",
					fileMode: filePerm,
					isDir:    false,
					size:     7,
					fileInfo: fileInfo{
						name:     ".dotfile",
						fileMode: filePerm,
						isDir:    false,
						size:     7,
					},
				},
				{
					name:     "c.txt",
					fileMode: filePerm,
					isDir:    false,
					size:     0,
					fileInfo: fileInfo{
						name:     "c.txt",
						fileMode: filePerm,
						isDir:    false,
						size:     0,
					},
				},
				{
					name:     "virtual.txt",
					fileMode: 0600,
					isDir:    false,
					size:     0,
					fileInfo: virtualFileInfo,
				},
			},
			wantErr: assert.NoError,
		},
		{
			name:     "no such dir",
			filePath: "nosuch/",
			wantErr:  assert.Error,
		},
	}

	for _, tt := range tests {
		fsys := initFS(t)
		t.Run(tt.name, func(t *testing.T) {
			entries, err := fsys.ReadDir(tt.filePath)
			tt.wantErr(t, err)

			for _, z := range lo.Zip2(entries, tt.want) {
				got, want := z.A, z.B
				assert.Equal(t, want.name, got.Name())
				assert.Equal(t, want.fileMode, got.Type(), want.name)
				assert.Equal(t, want.isDir, got.IsDir(), want.name)

				fi, err := got.Info()
				require.NoError(t, err)
				assertFileInfo(t, want.fileInfo, fi)
			}
		})
	}
}

func TestFS_Open(t *testing.T) {
	type file struct {
		fileInfo fileInfo
		body     string
	}

	tests := []struct {
		name     string
		filePath string
		want     file
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "ordinary file",
			filePath: "hello.txt",
			want: file{
				fileInfo: helloFileInfo,
				body:     "hello world",
			},
			wantErr: assert.NoError,
		},
		{
			name:     "virtual file",
			filePath: "a/b/c/virtual.txt",
			want: file{
				fileInfo: virtualFileInfo,
				body:     "virtual",
			},
			wantErr: assert.NoError,
		},
		{
			name:     "dir",
			filePath: "a/b/c",
			want: file{
				fileInfo: cdirFileInfo,
			},
			wantErr: assert.NoError,
		},
		{
			name:     "no such file",
			filePath: "nosuch.txt",
			wantErr:  assert.Error,
		},
	}

	for _, tt := range tests {
		fsys := initFS(t)
		t.Run(tt.name, func(t *testing.T) {
			f, err := fsys.Open(tt.filePath)
			tt.wantErr(t, err)
			if f == nil {
				return
			}
			defer func() {
				require.NoError(t, f.Close())
			}()

			fi, err := f.Stat()
			require.NoError(t, err)
			assertFileInfo(t, tt.want.fileInfo, fi)

			if tt.want.body != "" {
				b, err := io.ReadAll(f)
				require.NoError(t, err)
				assert.Equal(t, tt.want.body, string(b))
			}
		})
	}
}

func TestFS_ReadFile(t *testing.T) {
	tests := []struct {
		name     string
		filePath string
		want     string
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name:     "ordinary file",
			filePath: "hello.txt",
			want:     "hello world",
			wantErr:  assert.NoError,
		},
		{
			name:     "virtual file",
			filePath: "a/b/c/virtual.txt",
			want:     "virtual",
			wantErr:  assert.NoError,
		},
		{
			name:     "no such file",
			filePath: "nosuch.txt",
			wantErr:  assert.Error,
		},
	}

	for _, tt := range tests {
		fsys := initFS(t)
		t.Run(tt.name, func(t *testing.T) {
			b, err := fsys.ReadFile(tt.filePath)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, string(b))
		})
	}
}

func TestFS_Sub(t *testing.T) {
	fsys := initFS(t)
	sub, err := fsys.Sub("a/b")
	require.NoError(t, err)

	data, err := sub.(fs.ReadFileFS).ReadFile("c/.dotfile")
	require.NoError(t, err)
	assert.Equal(t, "dotfile", string(data))
}

func TestFS_Glob(t *testing.T) {
	tests := []struct {
		name    string
		pattern string
		want    []string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "root",
			pattern: "*",
			want: []string{
				"a",
				"hello.txt",
			},
			wantErr: assert.NoError,
		},
		{
			name:    "pattern",
			pattern: "*/b/c/*.txt",
			want: []string{
				"a/b/c/c.txt",
				"a/b/c/virtual.txt",
			},
			wantErr: assert.NoError,
		},
		{
			name:    "no such",
			pattern: "nosuch",
			wantErr: assert.NoError,
		},
	}

	for _, tt := range tests {
		fsys := initFS(t)
		t.Run(tt.name, func(t *testing.T) {
			results, err := fsys.Glob(tt.pattern)
			tt.wantErr(t, err)
			assert.Equal(t, tt.want, results)
		})
	}
}

func TestFS_Remove(t *testing.T) {
	tests := []struct {
		name    string
		path    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name:    "ordinary file",
			path:    "hello.txt",
			wantErr: assert.NoError,
		},
		{
			name:    "nested file",
			path:    "a/b/b.txt",
			wantErr: assert.NoError,
		},
		{
			name:    "virtual file",
			path:    "a/b/c/virtual.txt",
			wantErr: assert.NoError,
		},
		{
			name:    "empty dir",
			path:    "a/b/empty",
			wantErr: assert.NoError,
		},
		{
			name:    "empty path",
			path:    "",
			wantErr: assert.NoError,
		},
		{
			name:    "non-empty dir",
			path:    "a/b/c",
			wantErr: assert.Error,
		},
	}

	for _, tt := range tests {
		fsys := initFS(t)
		t.Run(tt.name, func(t *testing.T) {
			err := fsys.Remove(tt.path)
			tt.wantErr(t, err)
			if err != nil || tt.path == "" {
				return
			}

			_, err = fsys.Stat(tt.path)
			require.ErrorIs(t, err, fs.ErrNotExist)
		})
	}
}

func TestFS_RemoveAll(t *testing.T) {
	fsys := initFS(t)
	t.Run("ordinary file", func(t *testing.T) {
		err := fsys.RemoveAll("hello.txt")
		require.NoError(t, err)
		_, err = fsys.Stat("hello.txt")
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
	t.Run("non-empty dir", func(t *testing.T) {
		err := fsys.RemoveAll("a/b")
		require.NoError(t, err)
		_, err = fsys.Stat("a/b/c/c.txt")
		require.ErrorIs(t, err, fs.ErrNotExist)
		_, err = fsys.Stat("a/b/c/.dotfile")
		require.ErrorIs(t, err, fs.ErrNotExist)
		_, err = fsys.Stat("a/b/c/virtual.txt")
		require.ErrorIs(t, err, fs.ErrNotExist)
	})
}

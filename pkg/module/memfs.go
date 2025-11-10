package module

import (
	"io"
	"io/fs"
	"path/filepath"
	"time"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/mapfs"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// memFS is a wrapper of mapfs.FS and can change its underlying file system
// at runtime. This implements fs.FS.
type memFS struct {
	current *mapfs.FS
}

// Open implements fs.FS.
func (m *memFS) Open(name string) (fs.File, error) {
	if m.current != nil {
		return m.current.Open(name)
	}
	// memFS is always a directory.
	if name == "." {
		return &emptyDir{}, nil
	}
	return nil, fs.ErrNotExist
}

// initialize changes the underlying memory file system with the given file path and contents.
//
// Note: it is always to safe swap the underlying FS with this API since this is called only at the beginning of
// Analyze interface call, which is not concurrently called per module instance.
func (m *memFS) initialize(filePath string, content xio.ReadSeekerAt) error {
	mfs := mapfs.New()
	if err := mfs.MkdirAll(filepath.Dir(filePath), fs.ModePerm); err != nil {
		return xerrors.Errorf("mapfs mkdir error: %w", err)
	}
	b, err := io.ReadAll(content)
	if err != nil {
		return xerrors.Errorf("read error: %w", err)
	}
	err = mfs.WriteVirtualFile(filePath, b, fs.ModePerm)
	if err != nil {
		return xerrors.Errorf("mapfs write error: %w", err)
	}

	m.current = mfs
	return nil
}

type emptyDir struct{}

func (emptyDir) Close() (err error)         { return }
func (emptyDir) Stat() (fs.FileInfo, error) { return fakeRootDirInfo{}, nil }
func (emptyDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: "/", Err: fs.ErrInvalid}
}

type fakeRootDirInfo struct{}

func (fakeRootDirInfo) Name() string                            { return "/" }
func (fakeRootDirInfo) Size() int64                             { return 0 }
func (fakeRootDirInfo) Mode() fs.FileMode                       { return fs.ModeDir | 0o500 }
func (fakeRootDirInfo) ModTime() time.Time                      { return time.Unix(0, 0) }
func (fakeRootDirInfo) IsDir() bool                             { return true }
func (fakeRootDirInfo) Sys() any                                { return nil }
func (emptyDir) ReadDir(int) (dirents []fs.DirEntry, err error) { return }

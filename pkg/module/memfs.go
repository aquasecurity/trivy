package module

import (
	"io"
	"io/fs"
	"path/filepath"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/memoryfs"
)

// memFS is a wrapper of memoryfs.FS and can change its underlying file system
// at runtime. This implements fs.FS.
type memFS struct {
	current *memoryfs.FS
}

// Open implements fs.FS.
func (m *memFS) Open(name string) (fs.File, error) {
	if m.current == nil {
		return nil, fs.ErrNotExist
	}
	return m.current.Open(name)
}

// initialize changes the underlying memory file system with the given file path and contents.
//
// Note: it is always to safe swap the underlying FS with this API since this is called only at the beginning of
// Analyze interface call, which is not concurrently called per module instance.
func (m *memFS) initialize(filePath string, content dio.ReadSeekerAt) (err error) {
	memfs := memoryfs.New()
	if err = memfs.MkdirAll(filepath.Dir(filePath), fs.ModePerm); err != nil {
		return xerrors.Errorf("memory fs mkdir error: %w", err)
	}
	err = memfs.WriteLazyFile(filePath, func() (io.Reader, error) {
		return content, nil
	}, fs.ModePerm)
	if err != nil {
		return xerrors.Errorf("memory fs write error: %w", err)
	}

	m.current = memfs
	return
}

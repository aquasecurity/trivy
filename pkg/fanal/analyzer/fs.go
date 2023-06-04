package analyzer

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/mapfs"
	"github.com/aquasecurity/trivy/pkg/syncx"
)

// CompositeFS contains multiple filesystems for post-analyzers
type CompositeFS struct {
	group AnalyzerGroup
	dir   string
	files *syncx.Map[Type, *mapfs.FS]
}

func NewCompositeFS(group AnalyzerGroup) (*CompositeFS, error) {
	tmpDir, err := os.MkdirTemp("", "analyzer-fs-*")
	if err != nil {
		return nil, xerrors.Errorf("unable to create temporary directory: %w", err)
	}

	return &CompositeFS{
		group: group,
		dir:   tmpDir,
		files: new(syncx.Map[Type, *mapfs.FS]),
	}, nil
}

// Write takes a file path and information, opens the file, copies its contents to a temporary file,
// and writes it to the virtual filesystem of each post-analyzer that requires the file.
func (c *CompositeFS) Write(filePath string, info os.FileInfo, opener Opener) error {
	// Get all post-analyzers that want to analyze the file
	atypes := c.group.RequiredPostAnalyzers(filePath, info)
	if len(atypes) == 0 {
		return nil
	}

	// Create a temporary file to which the file in the layer will be copied
	// so that all the files will not be loaded into memory
	f, err := os.CreateTemp(c.dir, "file-*")
	if err != nil {
		return xerrors.Errorf("create temp error: %w", err)
	}
	defer f.Close()

	// Open a file in the layer
	r, err := opener()
	if err != nil {
		return xerrors.Errorf("file open error: %w", err)
	}
	defer r.Close()

	// Copy file content into the temporary file
	if _, err = io.Copy(f, r); err != nil {
		return xerrors.Errorf("copy error: %w", err)
	}

	if err = os.Chmod(f.Name(), info.Mode()); err != nil {
		return xerrors.Errorf("chmod error: %w", err)
	}

	// Create fs.FS for each post-analyzer that wants to analyze the current file
	for _, a := range atypes {
		analyzerFS, _ := c.files.LoadOrStore(a, mapfs.New())
		if dir := filepath.Dir(filePath); dir != "." {
			if err = analyzerFS.MkdirAll(dir, os.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
				return xerrors.Errorf("mapfs mkdir error: %w", err)
			}
		}
		err = analyzerFS.WriteFile(filePath, f.Name())
		if err != nil {
			return xerrors.Errorf("mapfs write error: %w", err)
		}
	}
	return nil
}

// CreateLink creates a link in the virtual filesystem that corresponds to a real file.
// The linked virtual file will have the same path as the real file path provided.
func (c *CompositeFS) CreateLink(dir, filePath string, info os.FileInfo) error {
	// Get all post-analyzers that want to analyze the file
	atypes := c.group.RequiredPostAnalyzers(filePath, info)
	if len(atypes) == 0 {
		return nil
	}

	// Create fs.FS for each post-analyzer that wants to analyze the current file
	for _, at := range atypes {
		// Since filesystem scanning may require access outside the specified path, (e.g. Terraform modules)
		// it allows "../" access with "WithUnderlyingRoot".
		mfs, _ := c.files.LoadOrStore(at, mapfs.New(mapfs.WithUnderlyingRoot(dir)))
		if d := filepath.Dir(filePath); d != "." {
			if err := mfs.MkdirAll(d, os.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
				return xerrors.Errorf("mapfs mkdir error: %w", err)
			}
		}
		if err := mfs.WriteFile(filePath, filepath.Join(dir, filePath)); err != nil {
			return xerrors.Errorf("mapfs write error: %w", err)
		}
	}
	return nil
}

// Set sets the fs.FS for the specified post-analyzer
func (c *CompositeFS) Set(t Type, fs *mapfs.FS) {
	c.files.Store(t, fs)
}

// Get returns the fs.FS for the specified post-analyzer
func (c *CompositeFS) Get(t Type) (*mapfs.FS, bool) {
	return c.files.Load(t)
}

// Cleanup removes the temporary directory
func (c *CompositeFS) Cleanup() error {
	return os.RemoveAll(c.dir)
}

package os

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"

	"golang.org/x/xerrors"
)

// Root is a traversal-resistant handle to a directory. It embeds *os.Root
// (https://pkg.go.dev/os#Root), so every name passed to its methods is confined
// to the directory. Root adds NewRoot and Join.
type Root struct {
	*os.Root
}

// NewRoot creates dir (0700) if necessary and opens it as a Root. Like
// os.OpenRoot, it returns an error if the directory cannot be opened.
func NewRoot(dir string) (*Root, error) {
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, xerrors.Errorf("failed to create directory %q: %w", dir, err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, xerrors.Errorf("failed to open root %q: %w", dir, err)
	}
	return &Root{Root: root}, nil
}

// Join validates name and returns it joined to the root directory. It rejects
// names that escape the root either literally (filepath.IsLocal handles "..",
// absolute paths, and escapes hidden behind a missing component) or through an
// existing symlink (the embedded os.Root). A name that does not exist yet is
// allowed, so the caller can resolve a destination before creating it.
//
// The result is a plain string, so it is not protected against a later symlink
// swap (TOCTOU): use it to hand a confined path to an external tool, and use the
// os.Root methods directly for ordinary I/O.
func (r *Root) Join(name string) (string, error) {
	if !filepath.IsLocal(name) {
		return "", xerrors.Errorf("name %q is not local", name)
	}
	// An existing symlink that escapes is rejected; a not-yet-existing name is fine.
	if _, err := r.Stat(name); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", xerrors.Errorf("%q: %w", name, err)
	}
	return filepath.Join(r.Name(), name), nil
}

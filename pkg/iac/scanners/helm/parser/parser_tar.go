package parser

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
	"github.com/aquasecurity/trivy/pkg/log"
)

var errSkipFS = errors.New("skip parse FS")

func (p *Parser) addTarToFS(archivePath string) (fs.FS, error) {
	tarFS := memoryfs.CloneFS(p.workingFS)

	file, err := tarFS.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar: %w", err)
	}
	defer file.Close()

	var tr *tar.Reader

	if detection.IsZip(archivePath) {
		zipped, err := gzip.NewReader(file)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		defer zipped.Close()
		tr = tar.NewReader(zipped)
	} else {
		tr = tar.NewReader(file)
	}

	checkExistedChart := true
	symlinks := make(map[string]string)

	for {
		header, err := tr.Next()
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to get next entry: %w", err)
		}

		name := filepath.ToSlash(header.Name)

		if checkExistedChart {
			// Do not add archive files to FS if the chart already exists
			// This can happen when the source chart is located next to an archived chart (with the `helm package` command)
			// The first level folder in the archive is equal to the Chart name
			if _, err := tarFS.Stat(path.Dir(archivePath) + "/" + path.Dir(name)); err == nil {
				return nil, errSkipFS
			}
			checkExistedChart = false
		}

		// get the individual path and extract to the current directory
		targetPath := path.Join(path.Dir(archivePath), path.Clean(name))

		link := filepath.ToSlash(header.Linkname)

		switch header.Typeflag {
		case tar.TypeDir:
			if err := tarFS.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, err
			}
		case tar.TypeReg:
			p.logger.Debug("Unpacking tar entry", log.FilePath(targetPath))
			if err := copyFile(tarFS, tr, targetPath); err != nil {
				return nil, err
			}
		case tar.TypeSymlink:
			if path.IsAbs(link) {
				p.logger.Debug("Symlink is absolute, skipping", log.String("link", link))
				continue
			}

			symlinks[targetPath] = path.Join(path.Dir(targetPath), link) // nolint:gosec // virtual file system is used
		default:
			return nil, fmt.Errorf("header type %q is not supported", header.Typeflag)
		}
	}

	for target, link := range symlinks {
		if err := copySymlink(tarFS, link, target); err != nil {
			return nil, fmt.Errorf("copy symlink error: %w", err)
		}
	}

	if err := tarFS.Remove(archivePath); err != nil {
		return nil, fmt.Errorf("remove tar from FS error: %w", err)
	}

	return tarFS, nil
}

func copySymlink(fsys *memoryfs.FS, src, dst string) error {
	fi, err := fsys.Stat(src)
	if err != nil {
		return nil
	}
	if fi.IsDir() {
		if err := copyDir(fsys, src, dst); err != nil {
			return fmt.Errorf("copy dir error: %w", err)
		}
		return nil
	}

	if err := copyFileLazy(fsys, src, dst); err != nil {
		return fmt.Errorf("copy file error: %w", err)
	}

	return nil
}

func copyFile(fsys *memoryfs.FS, src io.Reader, dst string) error {
	if err := fsys.MkdirAll(path.Dir(dst), fs.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("mkdir error: %w", err)
	}

	b, err := io.ReadAll(src)
	if err != nil {
		return fmt.Errorf("read error: %w", err)
	}

	if err := fsys.WriteFile(dst, b, fs.ModePerm); err != nil {
		return fmt.Errorf("write file error: %w", err)
	}

	return nil
}

func copyDir(fsys *memoryfs.FS, src, dst string) error {
	walkFn := func(filePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			return nil
		}

		dst := path.Join(dst, filePath[len(src):])

		if err := copyFileLazy(fsys, filePath, dst); err != nil {
			return fmt.Errorf("copy file error: %w", err)
		}
		return nil
	}

	return fs.WalkDir(fsys, src, walkFn)
}

func copyFileLazy(fsys *memoryfs.FS, src, dst string) error {
	if err := fsys.MkdirAll(path.Dir(dst), fs.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
		return fmt.Errorf("mkdir error: %w", err)
	}
	return fsys.WriteLazyFile(dst, func() (io.Reader, error) {
		f, err := fsys.Open(src)
		if err != nil {
			return nil, err
		}
		return f, nil
	}, fs.ModePerm)
}

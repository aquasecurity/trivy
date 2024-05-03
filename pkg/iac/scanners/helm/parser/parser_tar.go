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

		if checkExistedChart {
			// Do not add archive files to FS if the chart already exists
			// This can happen when the source chart is located next to an archived chart (with the `helm package` command)
			// The first level folder in the archive is equal to the Chart name
			if _, err := tarFS.Stat(filepath.Dir(archivePath) + "/" + filepath.Dir(header.Name)); err == nil {
				return nil, errSkipFS
			}
			checkExistedChart = false
		}

		// get the individual path and extract to the current directory
		targetPath := path.Join(filepath.Dir(archivePath), filepath.Clean(header.Name))

		switch header.Typeflag {
		case tar.TypeDir:
			if err := tarFS.MkdirAll(targetPath, os.FileMode(header.Mode)); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, err
			}
		case tar.TypeReg:
			p.debug.Log("Unpacking tar entry %s", targetPath)
			if err := copyFile(tarFS, tr, targetPath); err != nil {
				return nil, err
			}
		case tar.TypeSymlink:
			if filepath.IsAbs(header.Linkname) {
				p.debug.Log("Symlink %s is absolute, skipping", header.Linkname)
				continue
			}

			symlinks[targetPath] = path.Join(filepath.Dir(targetPath), header.Linkname)
		default:
			return nil, fmt.Errorf("header type %q is not supported", header.Typeflag)
		}
	}

	for target, link := range symlinks {
		fi, err := tarFS.Stat(link)
		if err != nil {
			p.debug.Log("stat error: %s", err)
			continue
		}
		if fi.IsDir() {
			if err := copyDir(tarFS, link, target); err != nil {
				return nil, fmt.Errorf("copy dir error: %w", err)
			}
			continue
		}

		f, err := tarFS.Open(link)
		if err != nil {
			return nil, fmt.Errorf("open symlink error: %w", err)
		}

		if err := copyFile(tarFS, f, target); err != nil {
			f.Close()
			return nil, fmt.Errorf("copy file error: %w", err)
		}
		f.Close()
	}

	if err := tarFS.Remove(archivePath); err != nil {
		return nil, fmt.Errorf("remove tar from FS error: %w", err)
	}

	return tarFS, nil
}

func copyFile(fsys *memoryfs.FS, src io.Reader, dst string) error {
	if err := fsys.MkdirAll(filepath.Dir(dst), fs.ModePerm); err != nil && !errors.Is(err, fs.ErrExist) {
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

func copyDir(fsys *memoryfs.FS, src string, dst string) error {
	walkFn := func(filePath string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if entry.IsDir() {
			return nil
		}

		dst := path.Join(dst, filePath[len(src):])

		f, err := fsys.Open(filePath)
		if err != nil {
			return err
		}

		if err := copyFile(fsys, f, dst); err != nil {
			return fmt.Errorf("copy file error: %w", err)
		}
		return nil
	}

	return fs.WalkDir(fsys, src, walkFn)
}

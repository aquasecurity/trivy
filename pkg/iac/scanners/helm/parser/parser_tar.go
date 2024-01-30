package parser

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/liamg/memoryfs"

	"github.com/aquasecurity/trivy/pkg/iac/detection"
)

var errSkipFS = errors.New("skip parse FS")

func (p *Parser) addTarToFS(path string) (fs.FS, error) {
	tarFS := memoryfs.CloneFS(p.workingFS)

	file, err := tarFS.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open tar: %w", err)
	}
	defer file.Close()

	var tr *tar.Reader

	if detection.IsZip(path) {
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
			if _, err := tarFS.Stat(filepath.Dir(path) + "/" + filepath.Dir(header.Name)); err == nil {
				return nil, errSkipFS
			}
			checkExistedChart = false
		}

		// get the individual path and extract to the current directory
		entryPath := header.Name

		switch header.Typeflag {
		case tar.TypeDir:
			if err := tarFS.MkdirAll(entryPath, os.FileMode(header.Mode)); err != nil && !errors.Is(err, fs.ErrExist) {
				return nil, err
			}
		case tar.TypeReg:
			writePath := filepath.Dir(path) + "/" + entryPath
			p.debug.Log("Unpacking tar entry %s", writePath)

			_ = tarFS.MkdirAll(filepath.Dir(writePath), fs.ModePerm)

			buf, err := copyChunked(tr, 1024)
			if err != nil {
				return nil, err
			}

			p.debug.Log("writing file contents to %s", writePath)
			if err := tarFS.WriteFile(writePath, buf.Bytes(), fs.ModePerm); err != nil {
				return nil, fmt.Errorf("write file error: %w", err)
			}
		default:
			return nil, fmt.Errorf("header type %q is not supported", header.Typeflag)
		}
	}

	if err := tarFS.Remove(path); err != nil {
		return nil, fmt.Errorf("failed to remove tar from FS: %w", err)
	}

	return tarFS, nil
}

func copyChunked(src io.Reader, chunkSize int64) (*bytes.Buffer, error) {
	buf := new(bytes.Buffer)
	for {
		if _, err := io.CopyN(buf, src, chunkSize); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, fmt.Errorf("failed to copy: %w", err)
		}
	}

	return buf, nil
}

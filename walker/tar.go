package walker

import (
	"archive/tar"
	"io"
	"io/ioutil"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

func WalkLayerTar(layer io.Reader, analyzeFn WalkFunc) ([]string, []string, error) {
	var opqDirs, whFiles []string
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		filePath := hdr.Name
		filePath = strings.TrimLeft(filepath.Clean(filePath), "/")
		fileDir, fileName := filepath.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}
		// etc/.wh.hostname
		if strings.HasPrefix(fileName, wh) {
			name := strings.TrimPrefix(fileName, wh)
			fpath := filepath.Join(fileDir, name)
			whFiles = append(whFiles, fpath)
			continue
		}

		if isIgnored(filePath) {
			continue
		}

		if hdr.Typeflag == tar.TypeSymlink || hdr.Typeflag == tar.TypeLink || hdr.Typeflag == tar.TypeReg {
			err = analyzeFn(filePath, hdr.FileInfo(), tarOnceOpener(tr))
			if err != nil {
				return nil, nil, xerrors.Errorf("failed to analyze file: %w", err)
			}
		}
	}
	return opqDirs, whFiles, nil
}

// tarOnceOpener reads a file once and the content is shared so that some analyzers can use the same data
func tarOnceOpener(r io.Reader) func() ([]byte, error) {
	var once sync.Once
	var b []byte
	var err error

	return func() ([]byte, error) {
		once.Do(func() {
			b, err = ioutil.ReadAll(r)
		})
		if err != nil {
			return nil, xerrors.Errorf("unable to read tar file: %w", err)
		}
		return b, nil
	}
}

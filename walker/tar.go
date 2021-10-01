package walker

import (
	"archive/tar"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

type LayerTar struct {
	walker
}

func NewLayerTar(skipFiles, skipDirs []string) LayerTar {
	return LayerTar{
		walker: newWalker(skipFiles, skipDirs),
	}
}

func (w LayerTar) Walk(layer io.Reader, analyzeFn WalkFunc) ([]string, []string, error) {
	var opqDirs, whFiles, skipDirs []string
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
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

		switch hdr.Typeflag {
		case tar.TypeDir:
			if w.shouldSkipDir(filePath) {
				skipDirs = append(skipDirs, filePath)
				continue
			}
		case tar.TypeSymlink, tar.TypeLink, tar.TypeReg:
			if w.shouldSkipFile(filePath) {
				continue
			}
		default:
			continue
		}

		if underSkippedDir(filePath, skipDirs) {
			continue
		}

		// A symbolic/hard link or regular file will reach here.
		err = analyzeFn(filePath, hdr.FileInfo(), w.fileOnceOpener(tr))
		if err != nil {
			return nil, nil, xerrors.Errorf("failed to analyze file: %w", err)
		}
	}
	return opqDirs, whFiles, nil
}

func underSkippedDir(filePath string, skipDirs []string) bool {
	for _, skipDir := range skipDirs {
		rel, err := filepath.Rel(skipDir, filePath)
		if err != nil {
			return false
		}
		if !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}

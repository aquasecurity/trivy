package walker

import (
	"archive/tar"
	"io"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/utils"
)

const (
	opq string = ".wh..wh..opq"
	wh  string = ".wh."
)

var parentDir = ".." + utils.PathSeparator

type LayerTar struct {
	skipFiles []string
	skipDirs  []string
}

func NewLayerTar(opt Option) LayerTar {
	return LayerTar{
		skipFiles: utils.CleanSkipPaths(opt.SkipFiles),
		skipDirs:  utils.CleanSkipPaths(opt.SkipDirs),
	}
}

func (w LayerTar) Walk(layer io.Reader, analyzeFn WalkFunc) ([]string, []string, error) {
	var opqDirs, whFiles, skippedDirs []string
	tr := tar.NewReader(layer)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		} else if err != nil {
			return nil, nil, xerrors.Errorf("failed to extract the archive: %w", err)
		}

		// filepath.Clean cannot be used since tar file paths should be OS-agnostic.
		filePath := path.Clean(hdr.Name)
		filePath = strings.TrimLeft(filePath, "/")
		fileDir, fileName := path.Split(filePath)

		// e.g. etc/.wh..wh..opq
		if opq == fileName {
			opqDirs = append(opqDirs, fileDir)
			continue
		}
		// etc/.wh.hostname
		if strings.HasPrefix(fileName, wh) {
			name := strings.TrimPrefix(fileName, wh)
			fpath := path.Join(fileDir, name)
			whFiles = append(whFiles, fpath)
			continue
		}

		switch hdr.Typeflag {
		case tar.TypeDir:
			if utils.SkipPath(filePath, w.skipDirs) {
				skippedDirs = append(skippedDirs, filePath)
				continue
			}
		case tar.TypeReg:
			if utils.SkipPath(filePath, w.skipFiles) {
				continue
			}
		// symlinks and hardlinks have no content in reader, skip them
		default:
			continue
		}

		if underSkippedDir(filePath, skippedDirs) {
			continue
		}

		// A regular file will reach here.
		if err = w.processFile(filePath, tr, hdr.FileInfo(), analyzeFn); err != nil {
			return nil, nil, xerrors.Errorf("failed to process the file: %w", err)
		}
	}
	return opqDirs, whFiles, nil
}

func (w LayerTar) processFile(filePath string, tr *tar.Reader, fi fs.FileInfo, analyzeFn WalkFunc) error {
	cf := newCachedFile(fi.Size(), tr)
	defer func() {
		// nolint
		_ = cf.Clean()
	}()

	if err := analyzeFn(filePath, fi, cf.Open); err != nil {
		return xerrors.Errorf("failed to analyze file: %w", err)
	}

	return nil
}

func underSkippedDir(filePath string, skipDirs []string) bool {
	for _, skipDir := range skipDirs {
		rel, err := filepath.Rel(skipDir, filePath)
		if err != nil {
			return false
		}
		if !strings.HasPrefix(rel, parentDir) {
			return true
		}
	}
	return false
}

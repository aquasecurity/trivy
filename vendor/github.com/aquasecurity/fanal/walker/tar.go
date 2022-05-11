package walker

import (
	"archive/tar"
	"bytes"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
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
		if err = w.processFile(filePath, tr, hdr.FileInfo(), analyzeFn); err != nil {
			return nil, nil, xerrors.Errorf("failed to process the file: %w", err)
		}
	}
	return opqDirs, whFiles, nil
}

func (w LayerTar) processFile(filePath string, tr *tar.Reader, fi fs.FileInfo, analyzeFn WalkFunc) error {
	tf := newTarFile(fi.Size(), tr)
	defer tf.Clean()

	if err := analyzeFn(filePath, fi, tf.Open); err != nil {
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
		if !strings.HasPrefix(rel, "../") {
			return true
		}
	}
	return false
}

// tarFile represents a file in a tar file.
type tarFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	content  []byte // It will be populated if this file is small
	filePath string // It will be populated if this file is large
}

func newTarFile(size int64, r io.Reader) tarFile {
	return tarFile{
		size:   size,
		reader: r,
	}
}

// Open opens a file in the tar file.
// If the file size is greater than or equal to threshold, it copies the content to a temp file and opens it next time.
// If the file size is less than threshold, it opens the file once and the content will be shared so that others analyzers can use the same data.
func (o *tarFile) Open() (dio.ReadSeekCloserAt, error) {
	o.once.Do(func() {
		// When the file is large, it will be written down to a temp file.
		if o.size >= ThresholdSize {
			f, err := os.CreateTemp("", "fanal-*")
			if err != nil {
				o.err = xerrors.Errorf("failed to create the temp file: %w", err)
				return
			}

			if _, err = io.Copy(f, o.reader); err != nil {
				o.err = xerrors.Errorf("failed to copy: %w", err)
				return
			}

			o.filePath = f.Name()
		} else {
			b, err := io.ReadAll(o.reader)
			if err != nil {
				o.err = xerrors.Errorf("unable to read the file: %w", err)
				return
			}
			o.content = b
		}
	})
	if o.err != nil {
		return nil, xerrors.Errorf("failed to open: %w", o.err)
	}

	return o.open()
}

func (o *tarFile) open() (dio.ReadSeekCloserAt, error) {
	if o.filePath != "" {
		f, err := os.Open(o.filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp file: %w", err)
		}
		return f, nil
	}

	return dio.NopCloser(bytes.NewReader(o.content)), nil
}

func (o *tarFile) Clean() error {
	return os.Remove(o.filePath)
}

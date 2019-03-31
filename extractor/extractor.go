package extractor

import (
	"io"

	"github.com/pkg/errors"
)

var (
	// ErrCouldNotExtract occurs when an extraction fails.
	ErrCouldNotExtract = errors.New("Could not extract the archive")
)

type FilesMap map[string][]byte

type Extractor interface {
	ExtractFiles(layer io.ReadCloser, filenames []string) (FilesMap, error)
}

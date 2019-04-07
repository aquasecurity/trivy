package extractor

import (
	"io"

	"github.com/pkg/errors"
)

var (
	// ErrCouldNotExtract occurs when an extraction fails.
	ErrCouldNotExtract = errors.New("Could not extract the archive")
)

type FileMap map[string][]byte

type Extractor interface {
	Extract(r io.ReadCloser, filenames []string) (FileMap, error)
}

package extractor

import (
	"context"
	"io"

	"github.com/pkg/errors"
)

var (
	// ErrCouldNotExtract occurs when an extraction fails.
	ErrCouldNotExtract = errors.New("Could not extract the archive")
)

type FileMap map[string][]byte

type Extractor interface {
	Extract(ctx context.Context, imageName string, filenames []string) (FileMap, error)
	ExtractFromFile(ctx context.Context, r io.Reader, filenames []string) (FileMap, error)
}

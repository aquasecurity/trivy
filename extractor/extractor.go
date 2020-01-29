package extractor

import (
	"context"
	"io"

	"github.com/aquasecurity/fanal/extractor/image"
)

type FileMap map[string][]byte
type OPQDirs []string

type Extractor interface {
	Extract(ctx context.Context, imageRef image.Reference, transports, filenames []string) (FileMap, error)
	ExtractFiles(layer io.Reader, filenames []string) (FileMap, OPQDirs, error)
}

package extractor

import (
	"context"
	"io"
)

type FileMap map[string][]byte
type OPQDirs []string

type Extractor interface {
	Extract(ctx context.Context, imageName string, filenames []string) (FileMap, error)
	ExtractFromFile(ctx context.Context, r io.Reader, filenames []string) (FileMap, error)
	SaveLocalImage(ctx context.Context, imageName string) (io.Reader, error)
	ExtractFiles(layer io.Reader, filenames []string) (FileMap, OPQDirs, error)
}

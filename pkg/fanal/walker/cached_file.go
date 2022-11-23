package walker

import (
	"bytes"
	"io"
	"os"
	"sync"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

// cachedFile represents a file cached in memory or storage according to the file size.
type cachedFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	threshold int64 //　Files larger than this threshold are written to file without being read into memory.

	content  []byte // It will be populated if this file is small
	filePath string // It will be populated if this file is large
}

func newCachedFile(size int64, r io.Reader, threshold int64) *cachedFile {
	return &cachedFile{
		size:      size,
		reader:    r,
		threshold: threshold,
	}
}

// Open opens a file and cache the file.
// If the file size is greater than or equal to threshold, it copies the content to a temp file and opens it next time.
// If the file size is less than threshold, it opens the file once and the content will be shared so that others analyzers can use the same data.
func (o *cachedFile) Open() (dio.ReadSeekCloserAt, error) {
	o.once.Do(func() {
		// When the file is large, it will be written down to a temp file.
		if o.size >= o.threshold {
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

func (o *cachedFile) open() (dio.ReadSeekCloserAt, error) {
	if o.filePath != "" {
		f, err := os.Open(o.filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp file: %w", err)
		}
		return f, nil
	}

	return dio.NopCloser(bytes.NewReader(o.content)), nil
}

func (o *cachedFile) Clean() error {
	return os.Remove(o.filePath)
}

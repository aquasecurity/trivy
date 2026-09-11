package walker

import (
	"bytes"
	"errors"
	"io"
	"os"
	"sync"

	"golang.org/x/xerrors"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xos "github.com/aquasecurity/trivy/pkg/x/os"
)

// cachedFile represents a file cached in memory or storage according to the file size.
type cachedFile struct {
	once sync.Once
	err  error

	size   int64
	reader io.Reader

	content  []byte // It will be populated if this file is small
	filePath string // It will be populated if this file is large
}

func newCachedFile(size int64, r io.Reader) *cachedFile {
	return &cachedFile{
		size:   size,
		reader: r,
	}
}

// Open opens a file and cache the file.
// If the file size is greater than or equal to threshold, it copies the content to a temp file and opens it next time.
// If the file size is less than threshold, it opens the file once and the content will be shared so that others analyzers can use the same data.
func (o *cachedFile) Open() (xio.ReadSeekCloserAt, error) {
	o.once.Do(func() {
		// When the file is large, it will be written down to a temp file.
		if o.size >= defaultSizeThreshold {
			f, err := xos.CreateTemp("", "cached-file-")
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
			// The size is known up front, from the archive entry or from the file system,
			// so the buffer is allocated once here rather than grown step by step the way
			// io.ReadAll does it.
			b := make([]byte, max(o.size, 0))
			n, err := io.ReadFull(o.reader, b)
			// io.ReadAll returned the bytes it managed to read when the reader ended early,
			// without an error. Keep that behaviour instead of failing on a partial read.
			if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				o.err = xerrors.Errorf("unable to read the file: %w", err)
				return
			}
			o.content = b[:n]
		}
	})
	if o.err != nil {
		return nil, xerrors.Errorf("failed to open: %w", o.err)
	}

	return o.open()
}

func (o *cachedFile) open() (xio.ReadSeekCloserAt, error) {
	if o.filePath != "" {
		f, err := os.Open(o.filePath)
		if err != nil {
			return nil, xerrors.Errorf("failed to open the temp file: %w", err)
		}
		return f, nil
	}

	return xio.NopCloser(bytes.NewReader(o.content)), nil
}

func (o *cachedFile) Clean() error {
	return os.Remove(o.filePath)
}

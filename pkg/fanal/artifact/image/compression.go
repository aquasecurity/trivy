package image

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"io"

	"github.com/klauspost/compress/zstd"
	"golang.org/x/xerrors"

	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// https://en.wikipedia.org/wiki/List_of_file_signatures
var (
	gzipMagicNumber = []byte{'\x1f', '\x8b'}
	zstdMagicNumber = []byte{'\x28', '\xb5', '\x2f', '\xfd'}
)

type decompressor struct {
	magicNumber []byte
	wrap        func(io.Reader) (io.ReadCloser, error)
}

var decompressors = []decompressor{
	{
		magicNumber: gzipMagicNumber,
		wrap: func(r io.Reader) (io.ReadCloser, error) {
			gr, err := gzip.NewReader(r)
			if err != nil {
				return nil, xerrors.Errorf("failed to create gzip reader: %w", err)
			}
			return gr, nil
		},
	},
	{
		magicNumber: zstdMagicNumber,
		wrap: func(r io.Reader) (io.ReadCloser, error) {
			zr, err := zstd.NewReader(r)
			if err != nil {
				return nil, xerrors.Errorf("failed to create zstd reader: %w", err)
			}
			return zr.IOReadCloser(), nil
		},
	},
}

// uncompressed checks if the reader contains compressed data and returns the decompressed reader
// or the original reader if the data is not compressed.
func uncompressed(rc io.Reader) (io.ReadCloser, error) {
	br := bufio.NewReader(rc)
	for _, dec := range decompressors {
		ok, err := hasMagicNumber(br, dec.magicNumber)
		if err != nil {
			return nil, xerrors.Errorf("failed to check file header: %w", err)
		}

		if ok {
			return dec.wrap(br)
		}
	}

	// decompression not required
	return &xio.ReadCloser{
		Reader:    rc,
		CloseFunc: func() error { return nil },
	}, nil
}

type peekReader interface {
	io.Reader
	Peek(n int) ([]byte, error)
}

func hasMagicNumber(pr peekReader, magicNumber []byte) (bool, error) {
	b, err := pr.Peek(len(magicNumber))
	if errors.Is(err, io.EOF) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	return bytes.Equal(b, magicNumber), nil
}

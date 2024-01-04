package io

import (
	"bytes"
	"io"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
)

func NewReadSeekerAt(r io.Reader) (dio.ReadSeekerAt, error) {
	if rr, ok := r.(dio.ReadSeekerAt); ok {
		return rr, nil
	}

	buff := bytes.NewBuffer([]byte{})
	if _, err := io.Copy(buff, r); err != nil {
		return nil, xerrors.Errorf("copy error: %w", err)
	}

	return bytes.NewReader(buff.Bytes()), nil
}

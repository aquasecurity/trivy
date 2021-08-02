package wheel

import (
	"bufio"
	"io"
	"net/textproto"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

// Parse parses METADATA file for library Name and Version
// currently does not parse its possible dependencies
// https://packaging.python.org/specifications/core-metadata/#requires-dist-multiple-use
func Parse(r io.Reader) ([]types.Library, error) {
	var libs []types.Library
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return libs, xerrors.Errorf("read MIME error: %w", err)
	}

	libs = append(libs, types.Library{
		Name:    h.Get("Name"),
		Version: h.Get("Version"),
		License: h.Get("License"),
	})

	return libs, nil
}

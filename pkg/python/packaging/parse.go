package packaging

import (
	"bufio"
	"io"
	"net/textproto"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

// Parse parses egg and wheel metadata.
// e.g. .egg-info/PKG-INFO and dist-info/METADATA
func Parse(r io.Reader) (types.Library, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return types.Library{}, xerrors.Errorf("read MIME error: %w", err)
	}

	return types.Library{
		Name:    h.Get("Name"),
		Version: h.Get("Version"),
		License: h.Get("License"),
	}, nil
}

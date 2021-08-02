package egg

import (
	"bufio"
	"io"
	"net/textproto"

	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"golang.org/x/xerrors"
)

func Parse(r io.Reader) ([]types.Library, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	if err != nil {
		return nil, xerrors.Errorf("read MIME error: %w", err)
	}

	return []types.Library{
		{
			Name:    h.Get("Name"),
			Version: h.Get("Version"),
			License: h.Get("License"),
		},
	}, nil
}

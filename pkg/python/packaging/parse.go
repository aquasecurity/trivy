package packaging

import (
	"bufio"
	"io"
	"net/textproto"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

// Parse parses egg and wheel metadata.
// e.g. .egg-info/PKG-INFO and dist-info/METADATA
func (*Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	if err != nil && err != io.EOF {
		return nil, nil, xerrors.Errorf("read MIME error: %w", err)
	}

	// "License-Expression" takes precedence as "License" is deprecated.
	// cf. https://peps.python.org/pep-0639/#deprecate-license-field
	var license string
	if l := h.Get("License-Expression"); l != "" {
		license = l
	} else if l := h.Get("License"); l != "" {
		license = l
	} else {
		for _, classifier := range h.Values("Classifier") {
			if strings.HasPrefix(classifier, "License :: ") {
				values := strings.Split(classifier, " :: ")
				license = values[len(values)-1]
				break
			}
		}
	}
	if license == "" && h.Get("License-File") != "" {
		license = "file://" + h.Get("License-File")
	}

	return []types.Library{
		{
			Name:    h.Get("Name"),
			Version: h.Get("Version"),
			License: license,
		},
	}, nil, nil
}

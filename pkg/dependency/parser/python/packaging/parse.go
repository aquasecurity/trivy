package packaging

import (
	"bufio"
	"errors"
	"io"
	"net/textproto"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

// Parse parses egg and wheel metadata.
// e.g. .egg-info/PKG-INFO and dist-info/METADATA
func (*Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	rd := textproto.NewReader(bufio.NewReader(r))
	h, err := rd.ReadMIMEHeader()
	if e := textproto.ProtocolError(""); errors.As(err, &e) {
		// A MIME header may contain bytes in the key or value outside the set allowed by RFC 7230.
		// cf. https://cs.opensource.google/go/go/+/a6642e67e16b9d769a0c08e486ba08408064df19
		// However, our required key/value could have been correctly parsed,
		// so we continue with the subsequent process.
		log.Logger.Debugf("MIME protocol error: %s", err)
	} else if err != nil && err != io.EOF {
		return nil, nil, xerrors.Errorf("read MIME error: %w", err)
	}

	name, version := h.Get("name"), h.Get("version")
	if name == "" || version == "" {
		return nil, nil, xerrors.New("name or version is empty")
	}

	// "License-Expression" takes precedence in accordance with https://peps.python.org/pep-0639/#deprecate-license-field
	// Although keep in mind that pep-0639 is still in draft.
	var license string
	if le := h.Get("License-Expression"); le != "" {
		license = le
	} else {
		// Get possible multiple occurrences of licenses from "Classifier: License" field
		// When present it should define the license whereas "License" would define any additional exceptions or modifications
		// ref. https://packaging.python.org/en/latest/specifications/core-metadata/#license
		var licenses []string
		for _, classifier := range h.Values("Classifier") {
			if strings.HasPrefix(classifier, "License :: ") {
				values := strings.Split(classifier, " :: ")
				licenseName := values[len(values)-1]
				// According to the classifier list https://pypi.org/classifiers/ there is one classifier which seems more like a grouping
				// It has no specific license definition (Classifier: License :: OSI Approved) - it is skipped
				if licenseName != "OSI Approved" {
					licenses = append(licenses, licenseName)
				}
			}
		}
		license = strings.Join(licenses, ", ")

		if l := h.Get("License"); l != "" {
			if len(licenses) != 0 {
				log.Logger.Infof("License acquired from METADATA classifiers may be subject to additional terms for [%s:%s]", name, version)
			} else {
				license = l
			}
		}

	}

	if license == "" && h.Get("License-File") != "" {
		license = "file://" + h.Get("License-File")
	}

	return []types.Library{
		{
			Name:    name,
			Version: version,
			License: license,
		},
	}, nil, nil
}

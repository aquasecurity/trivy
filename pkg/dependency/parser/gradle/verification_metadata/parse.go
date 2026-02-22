package verification_metadata

import (
	"context"
	"encoding/xml"
	"fmt"

	"golang.org/x/net/html/charset"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// VerificationMetadata models gradle/verification-metadata.xml
type VerificationMetadata struct {
	Components Components `xml:"components"`
}

type Components struct {
	Component []Component `xml:"component"`
}

type Component struct {
	Group   string `xml:"group,attr"`
	Name    string `xml:"name,attr"`
	Version string `xml:"version,attr"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	vm := &VerificationMetadata{}
	decoder := xml.NewDecoder(r)
	decoder.CharsetReader = charset.NewReaderLabel
	if err := decoder.Decode(vm); err != nil {
		return nil, nil, fmt.Errorf("gradle verification metadata error: read all: %w", err)
	}
	components := vm.Components.Component

	packages := make([]ftypes.Package, 0, len(components))
	for _, c := range components {
		if c.Group == "" || c.Name == "" || c.Version == "" {
			continue
		}
		coordinates := fmt.Sprintf("%s:%s", c.Group, c.Name)
		id := fmt.Sprintf("%s:%s", coordinates, c.Version)
		packages = append(packages, ftypes.Package{ID: id, Name: coordinates, Version: c.Version})
	}

	if len(packages) == 0 {
		return nil, nil, nil
	}

	return packages, []ftypes.Dependency{}, nil
}

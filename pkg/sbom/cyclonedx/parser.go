package cyclonedx

import (
	"encoding/json"
	"io"
	"path/filepath"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

type Parser struct {
	extension string
}

func NewParser(name string) *Parser {
	return &Parser{
		extension: filepath.Ext(name),
	}
}

func NewTrivyBOM(r io.Reader, ext string) (CycloneDX, error) {
	b := CycloneDX{}
	switch ext {
	case ".json":
		if err := json.NewDecoder(r).Decode(&b); err != nil {
			return CycloneDX{}, xerrors.Errorf("failed to json decode: %w", err)
		}
		return b, nil
	case ".xml":
		// TODO: not supported yet
	}
	return CycloneDX{}, xerrors.Errorf("invalid cycloneDX format: %s", ext)
}

func (p Parser) Parse(r io.Reader) (string, *ftypes.OS, []ftypes.PackageInfo, []ftypes.Application, error) {
	b, err := NewTrivyBOM(r, p.extension)
	if err != nil {
		return "", nil, nil, nil, xerrors.Errorf("failed to new Trivy BOM: %w", err)
	}

	if b.Components == nil {
		return b.SerialNumber, nil, nil, nil, nil
	}

	return b.parse()
}

func (p Parser) Type() sbom.SBOMFormat {
	return FormatCycloneDX
}

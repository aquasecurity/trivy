package pipenv

import (
	"io"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type lockFile struct {
	Default map[string]dependency `json:"default"`
}
type dependency struct {
	Version   string `json:"version"`
	StartLine int
	EndLine   int
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile lockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read packages.lock.json: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode Pipenv.lock: %w", err)
	}

	var pkgs []ftypes.Package
	for pkgName, dep := range lockFile.Default {
		pkgs = append(pkgs, ftypes.Package{
			Name:    pkgName,
			Version: strings.TrimLeft(dep.Version, "="),
			Locations: []ftypes.Location{
				{
					StartLine: dep.StartLine,
					EndLine:   dep.EndLine,
				},
			},
		})
	}
	return pkgs, nil, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *dependency) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

package pipenv

import (
	"io"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
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

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var lockFile lockFile
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read packages.lock.json: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode Pipenv.lock: %w", err)
	}

	var libs []types.Library
	for pkgName, dependency := range lockFile.Default {
		libs = append(libs, types.Library{
			Name:    pkgName,
			Version: strings.TrimLeft(dependency.Version, "="),
			Locations: []types.Location{
				{
					StartLine: dependency.StartLine,
					EndLine:   dependency.EndLine,
				},
			},
		})
	}
	return libs, nil, nil
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

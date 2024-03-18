package core_deps

import (
	"io"
	"strings"

	"github.com/liamg/jfather"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var depsFile dotNetDependencies

	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}
	if err := jfather.Unmarshal(input, &depsFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .deps.json file: %w", err)
	}

	var libraries []types.Library
	for nameVer, lib := range depsFile.Libraries {
		if !strings.EqualFold(lib.Type, "package") {
			continue
		}

		split := strings.Split(nameVer, "/")
		if len(split) != 2 {
			// Invalid name
			log.Logger.Warnf("Cannot parse .NET library version from: %s", nameVer)
			continue
		}

		libraries = append(libraries, types.Library{
			Name:    split[0],
			Version: split[1],
			Locations: []types.Location{
				{
					StartLine: lib.StartLine,
					EndLine:   lib.EndLine,
				},
			},
		})
	}

	return libraries, nil, nil
}

type dotNetDependencies struct {
	Libraries map[string]dotNetLibrary `json:"libraries"`
}

type dotNetLibrary struct {
	Type      string `json:"type"`
	StartLine int
	EndLine   int
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *dotNetLibrary) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

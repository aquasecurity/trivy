package lockfile

import (
	"io"
	"slices"
	"sort"

	"github.com/liamg/jfather"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

// lockfile format defined at: https://stringbean.github.io/sbt-dependency-lock/file-formats/version-1.html
type sbtLockfile struct {
	Version      int                     `json:"lockVersion"`
	Dependencies []sbtLockfileDependency `json:"dependencies"`
}

type sbtLockfileDependency struct {
	Organization   string   `json:"org"`
	Name           string   `json:"name"`
	Version        string   `json:"version"`
	Configurations []string `json:"configurations"`
	StartLine      int
	EndLine        int
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockfile sbtLockfile
	input, err := io.ReadAll(r)

	if err != nil {
		return nil, nil, xerrors.Errorf("failed to read sbt lockfile: %w", err)
	}
	if err := jfather.Unmarshal(input, &lockfile); err != nil {
		return nil, nil, xerrors.Errorf("JSON decoding failed: %w", err)
	}

	var libraries ftypes.Packages

	for _, dep := range lockfile.Dependencies {
		if slices.ContainsFunc(dep.Configurations, isIncludedConfig) {
			name := dep.Organization + ":" + dep.Name
			libraries = append(libraries, ftypes.Package{
				ID:      dependency.ID(ftypes.Sbt, name, dep.Version),
				Name:    name,
				Version: dep.Version,
				Locations: []ftypes.Location{
					{
						StartLine: dep.StartLine,
						EndLine:   dep.EndLine,
					},
				},
			})
		}
	}

	sort.Sort(libraries)
	return libraries, nil, nil
}

// UnmarshalJSONWithMetadata needed to detect start and end lines of deps
func (t *sbtLockfileDependency) UnmarshalJSONWithMetadata(node jfather.Node) error {
	if err := node.Decode(&t); err != nil {
		return err
	}
	// Decode func will overwrite line numbers if we save them first
	t.StartLine = node.Range().Start.Line
	t.EndLine = node.Range().End.Line
	return nil
}

func isIncludedConfig(config string) bool {
	return config == "compile" || config == "runtime"
}

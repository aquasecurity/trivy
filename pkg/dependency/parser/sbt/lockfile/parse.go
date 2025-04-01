package lockfile

import (
	"io"
	"slices"
	"sort"

	"github.com/go-json-experiment/json"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
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
	xjson.Location
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
	if err = json.Unmarshal(input, &lockfile, json.WithUnmarshalers(xjson.UnmarshalerWithObjectLocation(input))); err != nil {
		return nil, nil, xerrors.Errorf("JSON decoding failed: %w", err)
	}

	var libraries ftypes.Packages

	for _, dep := range lockfile.Dependencies {
		if slices.ContainsFunc(dep.Configurations, isIncludedConfig) {
			name := dep.Organization + ":" + dep.Name
			libraries = append(libraries, ftypes.Package{
				ID:        dependency.ID(ftypes.Sbt, name, dep.Version),
				Name:      name,
				Version:   dep.Version,
				Locations: []ftypes.Location{dep.Location.Location},
			})
		}
	}

	sort.Sort(libraries)
	return libraries, nil, nil
}

func isIncludedConfig(config string) bool {
	return config == "compile" || config == "runtime"
}

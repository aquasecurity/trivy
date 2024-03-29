package pub

import (
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	idFormat      = "%s@%s"
	transitiveDep = "transitive"
)

// Parser is a parser for pubspec.lock
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type lock struct {
	Packages map[string]Dep `yaml:"packages"`
}

type Dep struct {
	Dependency string `yaml:"dependency"`
	Version    string `yaml:"version"`
}

func (Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	l := &lock{}
	if err := yaml.NewDecoder(r).Decode(&l); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pubspec.lock: %w", err)
	}
	var libs []types.Library
	for name, dep := range l.Packages {
		// We would like to exclude dev dependencies, but we cannot identify
		// which indirect dependencies were introduced by dev dependencies
		// as there are 3 dependency types, "direct main", "direct dev" and "transitive".
		// It will be confusing if we exclude direct dev dependencies and include transitive dev dependencies.
		// We decided to keep all dev dependencies until Pub will add support for "transitive main" and "transitive dev".
		lib := types.Library{
			ID:       dependency.ID(ftypes.Pub, name, dep.Version),
			Name:     name,
			Version:  dep.Version,
			Indirect: dep.Dependency == transitiveDep,
		}
		libs = append(libs, lib)
	}

	return libs, nil, nil
}

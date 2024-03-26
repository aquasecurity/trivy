package pub

import (
	"strings"

	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	transitiveDep = "transitive"
)

// Parser is a parser for pubspec.lock
type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

type lock struct {
	Packages map[string]Dep    `yaml:"packages"`
	Sdks     map[string]string `yaml:"sdks"`
}

type Dep struct {
	Dependency  string      `yaml:"dependency"`
	Version     string      `yaml:"version"`
	Source      string      `yaml:"source"`
	Description Description `yaml:"description"`
}

type Description string

func (Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	l := &lock{}
	if err := yaml.NewDecoder(r).Decode(&l); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pubspec.lock: %w", err)
	}
	var libs []types.Library
	for name, dep := range l.Packages {
		// Some dependencies use one of the SDK versions.
		// In this case dep.Version == `0.0.0`.
		// We can't get versions for these dependencies.
		// Therefore, we use the first version of the SDK constraint specified in the Description.
		// See https://github.com/aquasecurity/trivy/issues/6017
		version := dep.Version
		if version == "0.0.0" && dep.Source == "sdk" {
			if constraint, ok := l.Sdks[string(dep.Description)]; ok {
				if v := firstVersionOfConstrain(constraint); v != "" {
					log.Logger.Infof("The first version of %q constraint was used for %q.", dep.Description, name)
					version = v
				}
			}
		}

		// We would like to exclude dev dependencies, but we cannot identify
		// which indirect dependencies were introduced by dev dependencies
		// as there are 3 dependency types, "direct main", "direct dev" and "transitive".
		// It will be confusing if we exclude direct dev dependencies and include transitive dev dependencies.
		// We decided to keep all dev dependencies until Pub will add support for "transitive main" and "transitive dev".
		lib := types.Library{
			ID:       dependency.ID(ftypes.Pub, name, version),
			Name:     name,
			Version:  version,
			Indirect: dep.Dependency == transitiveDep,
		}
		libs = append(libs, lib)
	}

	return libs, nil, nil
}

// firstVersionOfConstrain returns the first acceptable version for constraint
func firstVersionOfConstrain(constraint string) string {
	// cf. https://dart.dev/tools/pub/dependencies#traditional-syntax
	switch {
	case strings.HasPrefix(constraint, ">="):
		constraint = strings.TrimPrefix(constraint, ">=")
		constraint, _, _ = strings.Cut(constraint, " ")
		return constraint
	case strings.HasPrefix(constraint, "^"):
		return strings.TrimPrefix(constraint, "^")
	}
	return ""
}

func (d *Description) UnmarshalYAML(value *yaml.Node) error {
	var tmp any
	if err := value.Decode(&tmp); err != nil {
		return err
	}
	// Description can be a string or a struct
	// We only need a string value for SDK mapping
	if desc, ok := tmp.(string); ok {
		*d = Description(desc)
	}
	return nil
}

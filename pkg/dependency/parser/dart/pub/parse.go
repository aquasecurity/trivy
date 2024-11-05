package pub

import (
	"golang.org/x/xerrors"
	"gopkg.in/yaml.v3"

	goversion "github.com/aquasecurity/go-version/pkg/version"
	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

const (
	directMain    = "direct main"
	directDev     = "direct dev"
	transitiveDep = "transitive"
)

// Parser is a parser for pubspec.lock
type Parser struct {
	logger        *log.Logger
	useMinVersion bool
}

func NewParser(useMinVersion bool) *Parser {
	return &Parser{
		logger:        log.WithPrefix("pub"),
		useMinVersion: useMinVersion,
	}
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

func (p Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	l := &lock{}
	if err := yaml.NewDecoder(r).Decode(&l); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode pubspec.lock: %w", err)
	}
	var pkgs []ftypes.Package
	for name, dep := range l.Packages {
		version := dep.Version
		if version == "0.0.0" && dep.Source == "sdk" && p.useMinVersion {
			version = p.findSDKVersion(l, name, dep)
		}

		// We would like to exclude dev dependencies, but we cannot identify
		// which indirect dependencies were introduced by dev dependencies
		// as there are 3 dependency types, "direct main", "direct dev" and "transitive".
		// It will be confusing if we exclude direct dev dependencies and include transitive dev dependencies.
		// We decided to keep all dev dependencies until Pub will add support for "transitive main" and "transitive dev".
		pkg := ftypes.Package{
			ID:           dependency.ID(ftypes.Pub, name, version),
			Name:         name,
			Version:      version,
			Relationship: p.relationship(dep.Dependency),
		}
		pkgs = append(pkgs, pkg)
	}

	return pkgs, nil, nil
}

// findSDKVersion detects the minimum version of the SDK constraint specified in the Description.
// If the constraint is not found, it returns the original version.
func (p Parser) findSDKVersion(l *lock, name string, dep Dep) string {
	// Some dependencies use one of the SDK versions.
	// In this case dep.Version == `0.0.0`.
	// We can't get versions for these dependencies.
	// Therefore, we use the minimum version of the SDK constraint specified in the Description.
	// See https://github.com/aquasecurity/trivy/issues/6017
	constraint, ok := l.Sdks[string(dep.Description)]
	if !ok {
		return dep.Version
	}

	v, err := minVersionOfConstrain(constraint)
	if err != nil {
		p.logger.Warn("Unable to get sdk version from constraint", log.Err(err))
		return dep.Version
	} else if v == "" {
		return dep.Version
	}
	p.logger.Info("Using the minimum version of the constraint from the sdk source", log.String("dep", name),
		log.String("constraint", constraint))
	return v
}

func (p Parser) relationship(dep string) ftypes.Relationship {
	switch dep {
	case directMain, directDev:
		return ftypes.RelationshipDirect
	case transitiveDep:
		return ftypes.RelationshipIndirect
	}
	return ftypes.RelationshipUnknown
}

// minVersionOfConstrain returns the minimum acceptable version for constraint
func minVersionOfConstrain(constraint string) (string, error) {
	css, err := goversion.NewConstraints(constraint)
	if err != nil {
		return "", xerrors.Errorf("unable to parse constraints: %w", err)
	}

	// Dart uses only `>=` and `^` operators:
	// cf. https://dart.dev/tools/pub/dependencies#traditional-syntax
	constraints := css.List()
	if len(constraints) == 0 || len(constraints[0]) == 0 {
		return "", nil
	}
	// We only need to get the minimum version from the range
	if constraints[0][0].Operator() != ">=" && constraints[0][0].Operator() != "^" {
		return "", nil
	}

	return constraints[0][0].Version(), nil
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

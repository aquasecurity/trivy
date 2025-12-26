package composer

import (
	"context"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type LockFile struct {
	Packages    []packageInfo `json:"packages"`
	PackagesDev []packageInfo `json:"packages-dev"`
}
type packageInfo struct {
	Name    string            `json:"name"`
	Version string            `json:"version"`
	Require map[string]string `json:"require"`
	License any               `json:"license"`
	xjson.Location
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("composer"),
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	pkgs := make(map[string]ftypes.Package)
	foundDeps := make(map[string][]string)

	// Production packages are parsed first to ensure they take precedence
	// when the same package exists in both "packages" and "packages-dev".
	p.parseProdPackages(lockFile, pkgs, foundDeps)
	p.parseDevPackages(lockFile, pkgs, foundDeps)

	// fill deps versions
	var deps ftypes.Dependencies
	for pkgID, depsOn := range foundDeps {
		var dependsOn []string
		for _, depName := range depsOn {
			if pkg, ok := pkgs[depName]; ok {
				dependsOn = append(dependsOn, pkg.ID)
				continue
			}
			p.logger.Debug("Unable to find version", log.String("name", depName))
		}
		sort.Strings(dependsOn)
		deps = append(deps, ftypes.Dependency{
			ID:        pkgID,
			DependsOn: dependsOn,
		})
	}

	pkgSlice := lo.Values(pkgs)
	sort.Sort(ftypes.Packages(pkgSlice))
	sort.Sort(deps)

	return pkgSlice, deps, nil
}

// parseProdPackages parses packages from the "packages" field in composer.lock.
func (p *Parser) parseProdPackages(lockFile LockFile, pkgs map[string]ftypes.Package, foundDeps map[string][]string) {
	p.parsePackages(lockFile.Packages, false, pkgs, foundDeps)
}

// parseDevPackages parses packages from the "packages-dev" field in composer.lock.
// Packages already present in pkgs (i.e., production packages) are skipped.
func (p *Parser) parseDevPackages(lockFile LockFile, pkgs map[string]ftypes.Package, foundDeps map[string][]string) {
	p.parsePackages(lockFile.PackagesDev, true, pkgs, foundDeps)
}

func (p *Parser) parsePackages(lockPkgs []packageInfo, isDev bool, pkgs map[string]ftypes.Package, foundDeps map[string][]string) {
	for _, lpkg := range lockPkgs {
		// Skip if the package already exists (production packages take precedence over dev packages)
		if _, ok := pkgs[lpkg.Name]; ok {
			continue
		}

		pkg := ftypes.Package{
			ID:           dependency.ID(ftypes.Composer, lpkg.Name, lpkg.Version),
			Name:         lpkg.Name,
			Version:      lpkg.Version,
			Relationship: ftypes.RelationshipUnknown, // composer.lock file doesn't have info about direct/indirect dependencies
			Licenses:     licenses(lpkg.License),
			Locations:    []ftypes.Location{ftypes.Location(lpkg.Location)},
			Dev:          isDev,
		}
		pkgs[pkg.Name] = pkg

		var dependsOn []string
		for depName := range lpkg.Require {
			// Require field includes required php version, skip this
			// Also skip PHP extensions
			if depName == "php" || strings.HasPrefix(depName, "ext") {
				continue
			}
			dependsOn = append(dependsOn, depName) // field uses range of versions, so later we will fill in the versions from the packages
		}
		if len(dependsOn) > 0 {
			foundDeps[pkg.ID] = dependsOn
		}
	}
}

// licenses returns slice of licenses from string, string with separators (`or`, `and`, etc.) or string array
// cf. https://getcomposer.org/doc/04-schema.md#license
func licenses(val any) []string {
	switch v := val.(type) {
	case string:
		if v != "" {
			return licensing.SplitLicenses(v)
		}
	case []any:
		var lics []string
		for _, l := range v {
			if lic, ok := l.(string); ok {
				lics = append(lics, lic)
			}
		}
		return lics
	}
	return nil
}

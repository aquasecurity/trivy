package swift

import (
	"context"
	"sort"
	"strings"

	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

// Parser is a parser for Package.resolved files
type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("swift"),
	}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile LockFile
	if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	var pkgs ftypes.Packages
	pins := lockFile.Object.Pins
	if lockFile.Version > 1 {
		pins = lockFile.Pins
	}
	for _, pin := range pins {
		name := pkgName(pin, lockFile.Version)

		// Skip packages for which we cannot resolve the version
		if pin.State.Version == "" && pin.State.Branch == "" {
			p.logger.Warn("Unable to resolve. Both the version and branch fields are empty.", log.String("name", name))
			continue
		}

		// A Pin can be resolved using `branch` without `version`.
		// e.g. https://github.com/element-hq/element-ios/blob/6a9bcc88ea37147efba8f0a7bcf3ec187f4a4011/Riot.xcworkspace/xcshareddata/swiftpm/Package.resolved#L84-L92
		version := lo.Ternary(pin.State.Version != "", pin.State.Version, pin.State.Branch)

		pkgs = append(pkgs, ftypes.Package{
			ID:        dependency.ID(ftypes.Swift, name, version),
			Name:      name,
			Version:   version,
			Locations: []ftypes.Location{ftypes.Location(pin.Location)},
		})
	}
	sort.Sort(pkgs)
	return pkgs, nil, nil
}

func pkgName(pin Pin, lockVersion int) string {
	// Package.resolved v1 uses `RepositoryURL`
	// v2 uses `Location`
	name := pin.RepositoryURL
	if lockVersion > 1 {
		name = pin.Loc
	}
	// Swift uses `https://github.com/<author>/<package>.git format
	// `.git` suffix can be omitted (take a look happy test)
	// Remove `https://` and `.git` to fit the same format
	name = strings.TrimPrefix(name, "https://")
	name = strings.TrimSuffix(name, ".git")
	return name
}

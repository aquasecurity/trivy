package pipenv

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/python"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
	xjson "github.com/aquasecurity/trivy/pkg/x/json"
)

type lockFile struct {
	Default map[string]dependency `json:"default"`
}
type dependency struct {
	Version string `json:"version"`
	xjson.Location
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var lockFile lockFile
	if err := xjson.UnmarshalRead(r, &lockFile); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode Pipenv.lock: %w", err)
	}

	var pkgs []ftypes.Package
	for pkgName, dep := range lockFile.Default {
		pkgs = append(pkgs, ftypes.Package{
			// Normalize the separators (PEP 503) so the same package is reported
			// under one name regardless of the file it was found in (e.g. `zope.interface`
			// in Pipfile.lock and `zope-interface` in poetry.lock). The case is
			// preserved, as the vulnerability matching is already case-insensitive.
			Name:      python.NormalizePkgName(pkgName, false),
			Version:   strings.TrimLeft(dep.Version, "="),
			Locations: []ftypes.Location{ftypes.Location(dep.Location)},
		})
	}
	return pkgs, nil, nil
}

package pipenv

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

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
			Name:      pkgName,
			Version:   strings.TrimLeft(dep.Version, "="),
			Locations: []ftypes.Location{ftypes.Location(dep.Location)},
		})
	}
	return pkgs, nil, nil
}

package config

import (
	"encoding/xml"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
)

type cfgPackageReference struct {
	XMLName         xml.Name `xml:"package"`
	TargetFramework string   `xml:"targetFramework,attr"`
	Version         string   `xml:"version,attr"`
	DevDependency   bool     `xml:"developmentDependency,attr"`
	ID              string   `xml:"id,attr"`
}

type config struct {
	XMLName  xml.Name              `xml:"packages"`
	Packages []cfgPackageReference `xml:"package"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var cfgData config
	if err := xml.NewDecoder(r).Decode(&cfgData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .config file: %w", err)
	}

	uniqueLibs := map[types.Library]struct{}{}
	for _, pkg := range cfgData.Packages {
		if pkg.ID == "" || pkg.DevDependency {
			continue
		}

		lib := types.Library{
			Name:    pkg.ID,
			Version: pkg.Version,
		}
		uniqueLibs[lib] = struct{}{}
	}

	var libs []types.Library
	for lib := range uniqueLibs {
		libs = append(libs, lib)
	}

	return libs, nil, nil
}

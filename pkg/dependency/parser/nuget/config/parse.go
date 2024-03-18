package config

import (
	"encoding/xml"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var cfgData config
	if err := xml.NewDecoder(r).Decode(&cfgData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode .config file: %w", err)
	}

	var libs []types.Library
	for _, pkg := range cfgData.Packages {
		if pkg.ID == "" || pkg.DevDependency {
			continue
		}

		lib := types.Library{
			Name:    pkg.ID,
			Version: pkg.Version,
		}

		libs = append(libs, lib)
	}

	return utils.UniqueLibraries(libs), nil, nil
}

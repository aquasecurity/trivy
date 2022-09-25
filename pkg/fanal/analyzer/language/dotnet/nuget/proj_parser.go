package nuget

import (
	"encoding/xml"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type projPackageReference struct {
	XMLName     xml.Name `xml:"PackageReference"`
	Version     string   `xml:"Version,attr"`
	PackageName string   `xml:"Include,attr"`
}

type projItemGroup struct {
	XMLName           xml.Name               `xml:"ItemGroup"`
	PackageReferences []projPackageReference `xml:"PackageReference"`
}

type projRoot struct {
	XMLName    xml.Name        `xml:"Project"`
	ItemGroups []projItemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewProjParser() types.Parser {
	return &Parser{}
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var projData projRoot
	if err := xml.NewDecoder(r).Decode(&projData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode proj file: %w", err)
	}

	libs := make([]types.Library, 0)
	for _, groups := range projData.ItemGroups {
		for _, pkg := range groups.PackageReferences {
			if pkg.PackageName == "" {
				continue
			}

			lib := types.Library{
				Name:    pkg.PackageName,
				Version: pkg.Version,
			}

			libs = append(libs, lib)
		}
	}

	return utils.UniqueLibraries(libs), nil, nil
}

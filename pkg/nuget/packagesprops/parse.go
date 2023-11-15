package packagesprops

import (
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	dio "github.com/aquasecurity/go-dep-parser/pkg/io"
	"github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/go-dep-parser/pkg/utils"
)

type pkg struct {
	Version            string `xml:"Version,attr"`
	UpdatePackageName  string `xml:"Update,attr"`
	IncludePackageName string `xml:"Include,attr"`
}

// https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L150
type itemGroup struct {
	PackageReferenceEntry []pkg `xml:"PackageReference"`
	PackageVersionEntry   []pkg `xml:"PackageVersion"`
}

type project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() types.Parser {
	return &Parser{}
}

func (p pkg) library() types.Library {
	// Update attribute is considered legacy, so preferring Include
	name := p.UpdatePackageName
	if p.IncludePackageName != "" {
		name = p.IncludePackageName
	}

	name = strings.TrimSpace(name)
	version := strings.TrimSpace(p.Version)
	return types.Library{
		ID:      utils.PackageID(name, version),
		Name:    name,
		Version: version,
	}
}

func shouldSkipLib(lib types.Library) bool {
	if len(lib.Name) == 0 || len(lib.Version) == 0 {
		return true
	}
	// *packages.props files don't contain variable resolution information.
	// So we need to skip them.
	if isVariable(lib.Name) || isVariable(lib.Version) {
		return true
	}
	return false
}

func isVariable(s string) bool {
	return strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")")
}

func (p *Parser) Parse(r dio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
	var configData project
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}

	var libs []types.Library
	for _, item := range configData.ItemGroups {
		for _, pkg := range append(item.PackageReferenceEntry, item.PackageVersionEntry...) {
			lib := pkg.library()
			if !shouldSkipLib(lib) {
				libs = append(libs, lib)
			}
		}
	}
	return utils.UniqueLibraries(libs), nil, nil
}

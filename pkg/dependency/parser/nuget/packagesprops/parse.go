package packagesprops

import (
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	"github.com/aquasecurity/trivy/pkg/dependency/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
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
		ID:      dependency.ID(ftypes.NuGet, name, version),
		Name:    name,
		Version: version,
	}
}

func shouldSkipLib(lib types.Library) bool {
	if lib.Name == "" || lib.Version == "" {
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

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]types.Library, []types.Dependency, error) {
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

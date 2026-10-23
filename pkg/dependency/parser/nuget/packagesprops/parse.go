package packagesprops

import (
	"context"
	"encoding/xml"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Pkg struct {
	Version            string `xml:"Version,attr"`
	UpdatePackageName  string `xml:"Update,attr"`
	IncludePackageName string `xml:"Include,attr"`
}

// https://github.com/dotnet/roslyn-tools/blob/b4c5220f5dfc4278847b6d38eff91cc1188f8066/src/RoslynInsertionTool/RoslynInsertionTool/CoreXT.cs#L150
type itemGroup struct {
	PackageReferenceEntry []Pkg `xml:"PackageReference"`
	PackageVersionEntry   []Pkg `xml:"PackageVersion"`
}

type project struct {
	XMLName    xml.Name    `xml:"Project"`
	ItemGroups []itemGroup `xml:"ItemGroup"`
}

type Parser struct{}

func NewParser() *Parser {
	return &Parser{}
}

func (p Pkg) Package() ftypes.Package {
	// Update attribute is considered legacy, so preferring Include
	name := p.UpdatePackageName
	if p.IncludePackageName != "" {
		name = p.IncludePackageName
	}

	name = strings.TrimSpace(name)
	version := exactVersion(strings.TrimSpace(p.Version))
	return ftypes.Package{
		ID:      dependency.ID(ftypes.NuGet, name, version),
		Name:    name,
		Version: version,
	}
}

// exactVersion returns the version a NuGet range pins exactly: "[4.7.0]" and "[4.7.0, 4.7.0]" give "4.7.0".
// Any other value, including ranges, floating versions and malformed brackets, is returned as is.
// https://learn.microsoft.com/en-us/nuget/concepts/package-versioning#version-ranges
func exactVersion(version string) string {
	inner, ok := strings.CutPrefix(version, "[")
	if !ok {
		return version
	}
	if inner, ok = strings.CutSuffix(inner, "]"); !ok {
		return version
	}
	if lower, upper, found := strings.Cut(inner, ","); found {
		if lower, upper = strings.TrimSpace(lower), strings.TrimSpace(upper); lower != upper {
			return version
		}
		inner = lower
	}
	inner = strings.TrimSpace(inner)
	// A variable such as "[$(Version)]" is unwrapped too, so that it is skipped like an unbracketed one.
	if inner == "" || strings.ContainsAny(inner, "[],*") || strings.ContainsAny(inner, "()") && !isVariable(inner) {
		return version
	}
	return inner
}

func shouldSkipPkg(pkg ftypes.Package) bool {
	if pkg.Name == "" || pkg.Version == "" {
		return true
	}
	// *packages.props files don't contain variable resolution information.
	// So we need to skip them.
	if isVariable(pkg.Name) || isVariable(pkg.Version) {
		return true
	}
	return false
}

func isVariable(s string) bool {
	return strings.HasPrefix(s, "$(") && strings.HasSuffix(s, ")")
}

func (p *Parser) Parse(_ context.Context, r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var configData project
	if err := xml.NewDecoder(r).Decode(&configData); err != nil {
		return nil, nil, xerrors.Errorf("failed to decode '*.packages.props' file: %w", err)
	}

	var pkgs []ftypes.Package
	for _, item := range configData.ItemGroups {
		for _, pkg := range append(item.PackageReferenceEntry, item.PackageVersionEntry...) {
			pkg := pkg.Package()
			if !shouldSkipPkg(pkg) {
				pkgs = append(pkgs, pkg)
			}
		}
	}
	return utils.UniquePackages(pkgs), nil, nil
}

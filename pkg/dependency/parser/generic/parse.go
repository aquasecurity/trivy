package generic

import (
	"github.com/aquasecurity/trivy/pkg/dependency"
	"io"

	"github.com/aquasecurity/jfather"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency/parser/utils"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	xio "github.com/aquasecurity/trivy/pkg/x/io"
)

type Dependency struct {
	Version   string `json:"version"`
	Source    string `json:"source"`
	Type      string `json:"type"`
	License   string `json:"license,omitempty"`
	Copyright string `json:"copyright,omitempty"`
	Checksum  string `json:"checksum,omitempty"`
}

type SourceFile struct {
	Version   string `json:"version"`
	Checksum  string `json:"checksum"`
	License   string `json:"license"`
	Copyright string `json:"copyright,omitempty"`
}

type GenericPackage struct {
	PackageName      string                `json:"packageName"`
	PackageVersion   string                `json:"packageVersion"`
	PackageLicense   string                `json:"packageLicense,omitempty"`
	PackageCopyright string                `json:"packageCopyright,omitempty"`
	Dependencies     map[string]Dependency `json:"dependencies"`
	SourceFiles      map[string]SourceFile `json:"sourceFiles,omitempty"`
}

type Parser struct {
	logger *log.Logger
}

func NewParser() *Parser {
	return &Parser{
		logger: log.WithPrefix("generic"),
	}
}

func (p *Parser) Parse(r xio.ReadSeekerAt) ([]ftypes.Package, []ftypes.Dependency, error) {
	var genericPackage GenericPackage
	input, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, xerrors.Errorf("read error: %w", err)
	}

	if err := jfather.Unmarshal(input, &genericPackage); err != nil {
		return nil, nil, xerrors.Errorf("decode error: %w", err)
	}

	var pkgs []ftypes.Package
	var deps []ftypes.Dependency

	// Add the main package
	mainPkg := ftypes.Package{
		ID:           packageID(genericPackage.PackageName, genericPackage.PackageVersion),
		Name:         genericPackage.PackageName,
		Version:      genericPackage.PackageVersion,
		Licenses:     []string{genericPackage.PackageLicense},
		Relationship: ftypes.RelationshipRoot,
	}
	pkgs = append(pkgs, mainPkg)

	// Add dependencies
	for depName, dep := range genericPackage.Dependencies {
		depPkg := ftypes.Package{
			ID:           packageID(depName, dep.Version),
			Name:         depName,
			Version:      dep.Version,
			Licenses:     []string{dep.License},
			Relationship: ftypes.RelationshipDirect,
		}
		pkgs = append(pkgs, depPkg)

		// Add dependency relationship
		deps = append(deps, ftypes.Dependency{
			ID:        mainPkg.ID,
			DependsOn: []string{depPkg.ID},
		})
	}

	// Add source files as packages
	for filePath, file := range genericPackage.SourceFiles {
		filePkg := ftypes.Package{
			ID:           packageID(filePath, file.Version),
			Name:         filePath,
			Version:      file.Version,
			Licenses:     []string{file.License},
			Relationship: ftypes.RelationshipDirect,
		}
		pkgs = append(pkgs, filePkg)

		// Add source file relationship
		deps = append(deps, ftypes.Dependency{
			ID:        mainPkg.ID,
			DependsOn: []string{filePkg.ID},
		})
	}

	return utils.UniquePackages(pkgs), deps, nil
}

func packageID(name, version string) string {
	return dependency.ID(ftypes.Generic, name, version)
}

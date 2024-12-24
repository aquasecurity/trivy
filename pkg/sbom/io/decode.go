package io

import (
	"context"
	"errors"
	"slices"
	"sort"
	"strconv"
	"sync"

	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

var (
	ErrPURLEmpty       = errors.New("purl empty error")
	ErrUnsupportedType = errors.New("unsupported type")
)

type Decoder struct {
	bom *core.BOM

	osID uuid.UUID
	pkgs map[uuid.UUID]*ftypes.Package
	apps map[uuid.UUID]*ftypes.Application

	logger *log.Logger
}

func NewDecoder(bom *core.BOM) *Decoder {
	return &Decoder{
		bom:    bom,
		pkgs:   make(map[uuid.UUID]*ftypes.Package),
		apps:   make(map[uuid.UUID]*ftypes.Application),
		logger: log.WithPrefix("sbom"),
	}
}

func (m *Decoder) Decode(ctx context.Context, sbom *types.SBOM) error {
	// Parse the root component
	if err := m.decodeRoot(sbom); err != nil {
		return xerrors.Errorf("failed to decode root component: %w", err)
	}

	// Parse all components
	if err := m.decodeComponents(ctx, sbom); err != nil {
		return xerrors.Errorf("failed to decode components: %w", err)
	}

	// Build dependency graph between packages
	m.buildDependencyGraph()

	// Add OS packages
	m.addOSPkgs(sbom)

	// Add language-specific packages
	m.addLangPkgs(sbom)

	// Add remaining packages
	if err := m.addOrphanPkgs(ctx, sbom); err != nil {
		return xerrors.Errorf("failed to aggregate packages: %w", err)
	}

	sort.Slice(sbom.Applications, func(i, j int) bool {
		if sbom.Applications[i].Type != sbom.Applications[j].Type {
			return sbom.Applications[i].Type < sbom.Applications[j].Type
		}
		return sbom.Applications[i].FilePath < sbom.Applications[j].FilePath
	})

	sbom.BOM = m.bom

	return nil
}

func (m *Decoder) decodeRoot(s *types.SBOM) error {
	root := m.bom.Root()
	if root == nil {
		return nil // No root found
	}

	var err error
	for _, prop := range root.Properties {
		switch prop.Name {
		case core.PropertyImageID:
			s.Metadata.ImageID = prop.Value
		case core.PropertySize:
			if s.Metadata.Size, err = strconv.ParseInt(prop.Value, 10, 64); err != nil {
				return xerrors.Errorf("failed to convert size: %w", err)
			}
		case core.PropertyRepoDigest:
			s.Metadata.RepoDigests = append(s.Metadata.RepoDigests, prop.Value)
		case core.PropertyDiffID:
			s.Metadata.DiffIDs = append(s.Metadata.DiffIDs, prop.Value)
		case core.PropertyRepoTag:
			s.Metadata.RepoTags = append(s.Metadata.RepoTags, prop.Value)
		}
	}
	return nil
}

func (m *Decoder) decodeComponents(ctx context.Context, sbom *types.SBOM) error {
	onceMultiOSWarn := sync.OnceFunc(func() {
		m.logger.WarnContext(ctx, "Multiple OS components are not supported, taking the first one and ignoring the rest")
	})

	for id, c := range m.bom.Components() {
		switch c.Type {
		case core.TypeOS:
			if m.osID != uuid.Nil {
				onceMultiOSWarn()
				continue
			}
			m.osID = id
			sbom.Metadata.OS = &ftypes.OS{
				Family: ftypes.OSType(c.Name),
				Name:   c.Version,
			}
			continue
		case core.TypeApplication:
			if app := m.decodeApplication(c); app.Type != "" {
				m.apps[id] = app
				continue
			}
		}

		// Third-party SBOMs may contain packages in types other than "Library"
		if c.Type == core.TypeLibrary || c.PkgIdentifier.PURL != nil {
			pkg, err := m.decodePackage(ctx, c)
			if errors.Is(err, ErrUnsupportedType) || errors.Is(err, ErrPURLEmpty) {
				continue
			} else if err != nil {
				return xerrors.Errorf("failed to decode package: %w", err)
			}
			m.pkgs[id] = pkg
		}
	}

	return nil
}

// buildDependencyGraph builds a dependency graph between packages
func (m *Decoder) buildDependencyGraph() {
	for id, rels := range m.bom.Relationships() {
		pkg, ok := m.pkgs[id]
		if !ok {
			continue
		}
		for _, rel := range rels {
			dep, ok := m.pkgs[rel.Dependency]
			if !ok {
				continue
			}
			pkg.DependsOn = append(pkg.DependsOn, dep.ID)
		}
		continue
	}
}

func (m *Decoder) decodeApplication(c *core.Component) *ftypes.Application {
	var app ftypes.Application
	for _, prop := range c.Properties {
		if prop.Name == core.PropertyType {
			app.Type = ftypes.LangType(prop.Value)
		}
	}

	// Aggregation Types use the name of the language (e.g. `Java`, `Python`, etc.) as the component name.
	// Other language files use the file path as their name.
	if !slices.Contains(ftypes.AggregatingTypes, app.Type) {
		app.FilePath = c.Name
	}
	return &app
}

func (m *Decoder) decodePackage(ctx context.Context, c *core.Component) (*ftypes.Package, error) {
	p := (*purl.PackageURL)(c.PkgIdentifier.PURL)
	if p == nil {
		m.logger.DebugContext(ctx, "Skipping a component without PURL",
			log.String("name", c.Name), log.String("version", c.Version))
		return nil, ErrPURLEmpty
	}

	pkg := p.Package()
	if p.Class() == types.ClassUnknown {
		m.logger.DebugContext(ctx, "Skipping a component with an unsupported type",
			log.String("name", c.Name), log.String("version", c.Version), log.String("type", p.Type))
		return nil, ErrUnsupportedType
	}
	pkg.Name = m.pkgName(pkg, c)
	pkg.ID = dependency.ID(p.LangType(), pkg.Name, p.Version) // Re-generate ID with the updated name

	var err error
	for _, prop := range c.Properties {
		switch prop.Name {
		case core.PropertyPkgID:
			pkg.ID = prop.Value
		case core.PropertyFilePath:
			pkg.FilePath = prop.Value
		case core.PropertySrcName:
			pkg.SrcName = prop.Value
		case core.PropertySrcVersion:
			pkg.SrcVersion = prop.Value
		case core.PropertySrcRelease:
			pkg.SrcRelease = prop.Value
		case core.PropertySrcEpoch:
			if pkg.SrcEpoch, err = strconv.Atoi(prop.Value); err != nil {
				return nil, xerrors.Errorf("invalid src epoch: %w", err)
			}
		case core.PropertyModularitylabel:
			pkg.Modularitylabel = prop.Value
		case core.PropertyLayerDigest:
			pkg.Layer.Digest = prop.Value
		case core.PropertyLayerDiffID:
			pkg.Layer.DiffID = prop.Value
		}
	}

	pkg.Identifier.BOMRef = c.PkgIdentifier.BOMRef
	pkg.Licenses = c.Licenses

	for _, f := range c.Files {
		if f.Path != "" && pkg.FilePath == "" {
			pkg.FilePath = f.Path
		}
		// An empty path represents a package digest
		if f.Path == "" && len(f.Digests) > 0 {
			pkg.Digest = f.Digests[0]
		}
	}

	if p.Class() == types.ClassOSPkg {
		m.fillSrcPkg(ctx, c, pkg)
	}

	return pkg, nil
}

// pkgName returns the package name.
// PURL loses case-sensitivity (e.g. Go, Npm, PyPI), so we have to use an original package name.
func (m *Decoder) pkgName(pkg *ftypes.Package, c *core.Component) string {
	p := c.PkgIdentifier.PURL

	// A name from PURL takes precedence for CocoaPods since it has subpath.
	if c.PkgIdentifier.PURL.Type == packageurl.TypeCocoapods {
		return pkg.Name
	}

	// `maven purl type` has no restrictions on using lowercase letters.
	// Also, `spdx-maven-plugin` uses `name` instead of `artifactId` for the `package name` field.
	// So we need to use `purl` for maven/gradle packages
	// See https://github.com/aquasecurity/trivy/issues/7007 for more information.
	if p.Type == packageurl.TypeMaven || p.Type == packageurl.TypeGradle {
		return pkg.Name
	}

	// TODO(backward compatibility): Remove after 03/2025
	// Bitnami used different pkg.Name and the name from PURL.
	// For backwards compatibility - we need to use PURL.
	// cf. https://github.com/aquasecurity/trivy/issues/6981
	if c.PkgIdentifier.PURL.Type == packageurl.TypeBitnami {
		return pkg.Name
	}

	if c.Group != "" {
		return c.Group + "/" + c.Name
	}
	return c.Name
}

func (m *Decoder) fillSrcPkg(ctx context.Context, c *core.Component, pkg *ftypes.Package) {
	if c.SrcName != "" && pkg.SrcName == "" {
		pkg.SrcName = c.SrcName
	}
	m.parseSrcVersion(ctx, pkg, c.SrcVersion)

	// Source info was added from component or properties
	if pkg.SrcName != "" && pkg.SrcVersion != "" {
		return
	}

	// Fill source package information for components in third-party SBOMs .
	if pkg.SrcName == "" {
		pkg.SrcName = pkg.Name
	}
	if pkg.SrcVersion == "" {
		pkg.SrcVersion = pkg.Version
	}
	if pkg.SrcRelease == "" {
		pkg.SrcRelease = pkg.Release
	}
	if pkg.SrcEpoch == 0 {
		pkg.SrcEpoch = pkg.Epoch
	}
}

// parseSrcVersion parses the version of the source package.
func (m *Decoder) parseSrcVersion(ctx context.Context, pkg *ftypes.Package, ver string) {
	if ver == "" {
		return
	}
	switch pkg.Identifier.PURL.Type {
	case packageurl.TypeRPM:
		v := rpmver.NewVersion(ver)
		pkg.SrcEpoch = v.Epoch()
		pkg.SrcVersion = v.Version()
		pkg.SrcRelease = v.Release()
	case packageurl.TypeDebian:
		v, err := debver.NewVersion(ver)
		if err != nil {
			m.logger.DebugContext(ctx, "Failed to parse Debian version", log.Err(err))
			return
		}
		pkg.SrcEpoch = v.Epoch()
		pkg.SrcVersion = v.Version()
		pkg.SrcRelease = v.Revision()
	}
}

// addOSPkgs traverses relationships and adds OS packages
func (m *Decoder) addOSPkgs(sbom *types.SBOM) {
	pkgs := m.traverseDependencies(m.osID)
	if len(pkgs) == 0 {
		return
	}
	sbom.Packages = []ftypes.PackageInfo{{Packages: pkgs}}
}

// addLangPkgs traverses relationships and adds language-specific packages
func (m *Decoder) addLangPkgs(sbom *types.SBOM) {
	for id, app := range m.apps {
		app.Packages = append(app.Packages, m.traverseDependencies(id)...)
		sbom.Applications = append(sbom.Applications, *app)
	}
}

// traverseDependencies recursively retrieves all packages that the specified component depends on.
// It starts from the given component ID and traverses the dependency tree, collecting all
// dependent packages. The collected packages are removed from m.pkgs to prevent duplicate
// processing. This ensures that all dependencies, including transitive ones, are properly
// captured and associated with their parent component.
func (m *Decoder) traverseDependencies(id uuid.UUID) ftypes.Packages {
	var pkgs ftypes.Packages
	for _, rel := range m.bom.Relationships()[id] {
		pkg, ok := m.pkgs[rel.Dependency]
		if !ok {
			continue
		}
		// Add the current package
		pkgs = append(pkgs, *pkg)
		delete(m.pkgs, rel.Dependency) // Delete the added package

		// Add the nested packages
		pkgs = append(pkgs, m.traverseDependencies(rel.Dependency)...)
	}
	return pkgs
}

// addOrphanPkgs adds orphan packages.
// Orphan packages are packages that are not related to any components.
func (m *Decoder) addOrphanPkgs(ctx context.Context, sbom *types.SBOM) error {
	osPkgMap := make(map[string]ftypes.Packages)
	langPkgMap := make(map[ftypes.LangType]ftypes.Packages)
	for _, pkg := range m.pkgs {
		p := (*purl.PackageURL)(pkg.Identifier.PURL)
		switch p.Class() {
		case types.ClassOSPkg:
			osPkgMap[p.Type] = append(osPkgMap[p.Type], *pkg)
		case types.ClassLangPkg:
			langType := p.LangType()
			langPkgMap[langType] = append(langPkgMap[langType], *pkg)
		}
	}

	if len(osPkgMap) > 1 {
		return xerrors.Errorf("multiple types of OS packages in SBOM are not supported (%q)", lo.Keys(osPkgMap))
	}

	// Add OS packages only when OS is detected.
	for _, pkgs := range osPkgMap {
		if sbom.Metadata.OS == nil || !sbom.Metadata.OS.Detected() {
			m.logger.WarnContext(ctx, "Ignore the OS package as no OS is detected.")
			break
		}

		// TODO: mismatch between the OS and the packages should be rejected.
		// e.g. OS: debian, Packages: rpm
		sort.Sort(pkgs)
		sbom.Packages = append(sbom.Packages, ftypes.PackageInfo{Packages: pkgs})

		break // Just take the first element
	}

	// Add language-specific packages
	for pkgType, pkgs := range langPkgMap {
		sort.Sort(pkgs)
		sbom.Applications = append(sbom.Applications, ftypes.Application{
			Type:     pkgType,
			Packages: pkgs,
		})
	}
	return nil
}

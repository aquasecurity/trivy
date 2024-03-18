package io

import (
	"errors"
	"slices"
	"sort"
	"strconv"

	debver "github.com/knqyf263/go-deb-version"
	rpmver "github.com/knqyf263/go-rpm-version"
	"github.com/package-url/packageurl-go"
	"go.uber.org/zap"
	"golang.org/x/exp/maps"
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
}

func NewDecoder(bom *core.BOM) *Decoder {
	return &Decoder{
		bom:  bom,
		pkgs: make(map[uuid.UUID]*ftypes.Package),
		apps: make(map[uuid.UUID]*ftypes.Application),
	}
}

func (m *Decoder) Decode(sbom *types.SBOM) error {
	// Parse the root component
	if err := m.decodeRoot(sbom); err != nil {
		return xerrors.Errorf("failed to decode root component: %w", err)
	}

	// Parse all components
	if err := m.decodeComponents(sbom); err != nil {
		return xerrors.Errorf("failed to decode components: %w", err)
	}

	// Build dependency graph between packages
	m.buildDependencyGraph()

	// Add OS packages
	m.addOSPkgs(sbom)

	// Add language-specific packages
	m.addLangPkgs(sbom)

	// Add remaining packages
	if err := m.addOrphanPkgs(sbom); err != nil {
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

func (m *Decoder) decodeComponents(sbom *types.SBOM) error {
	for id, c := range m.bom.Components() {
		switch c.Type {
		case core.TypeOS:
			if m.osID != uuid.Nil {
				return xerrors.New("multiple OS components are not supported")
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
		if c.Type == core.TypeLibrary || c.PkgID.PURL != nil {
			pkg, err := m.decodeLibrary(c)
			if errors.Is(err, ErrUnsupportedType) || errors.Is(err, ErrPURLEmpty) {
				continue
			} else if err != nil {
				return xerrors.Errorf("failed to decode library: %w", err)
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

func (m *Decoder) decodeLibrary(c *core.Component) (*ftypes.Package, error) {
	p := (*purl.PackageURL)(c.PkgID.PURL)
	if p == nil {
		log.Logger.Debugw("Skipping a component without PURL",
			zap.String("name", c.Name), zap.String("version", c.Version))
		return nil, ErrPURLEmpty
	}

	pkg := p.Package()
	if p.Class() == types.ClassUnknown {
		log.Logger.Debugw("Skipping a component with an unsupported type",
			zap.String("name", c.Name), zap.String("version", c.Version), zap.String("type", p.Type))
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

	pkg.Identifier.BOMRef = c.PkgID.BOMRef
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
		m.fillSrcPkg(c, pkg)
	}

	return pkg, nil
}

// pkgName returns the package name.
// PURL loses case-sensitivity (e.g. Go, Npm, PyPI), so we have to use an original package name.
func (m *Decoder) pkgName(pkg *ftypes.Package, c *core.Component) string {
	p := c.PkgID.PURL

	// A name from PURL takes precedence for CocoaPods since it has subpath.
	if c.PkgID.PURL.Type == packageurl.TypeCocoapods {
		return pkg.Name
	}

	if c.Group != "" {
		if p.Type == packageurl.TypeMaven || p.Type == packageurl.TypeGradle {
			return c.Group + ":" + c.Name
		}
		return c.Group + "/" + c.Name
	}
	return c.Name
}

func (m *Decoder) fillSrcPkg(c *core.Component, pkg *ftypes.Package) {
	if c.SrcName != "" && pkg.SrcName == "" {
		pkg.SrcName = c.SrcName
	}
	m.parseSrcVersion(pkg, c.SrcVersion)

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
func (m *Decoder) parseSrcVersion(pkg *ftypes.Package, ver string) {
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
			log.Logger.Debugw("Failed to parse Debian version", zap.Error(err))
			return
		}
		pkg.SrcEpoch = v.Epoch()
		pkg.SrcVersion = v.Version()
		pkg.SrcRelease = v.Revision()
	}
}

// addOSPkgs traverses relationships and adds OS packages
func (m *Decoder) addOSPkgs(sbom *types.SBOM) {
	var pkgs []ftypes.Package
	for _, rel := range m.bom.Relationships()[m.osID] {
		pkg, ok := m.pkgs[rel.Dependency]
		if !ok {
			continue
		}
		pkgs = append(pkgs, *pkg)
		delete(m.pkgs, rel.Dependency) // Delete the added package
	}
	if len(pkgs) == 0 {
		return
	}
	sbom.Packages = []ftypes.PackageInfo{{Packages: pkgs}}
}

// addLangPkgs traverses relationships and adds language-specific packages
func (m *Decoder) addLangPkgs(sbom *types.SBOM) {
	for id, app := range m.apps {
		for _, rel := range m.bom.Relationships()[id] {
			pkg, ok := m.pkgs[rel.Dependency]
			if !ok {
				continue
			}
			app.Libraries = append(app.Libraries, *pkg)
			delete(m.pkgs, rel.Dependency) // Delete the added package
		}
		sbom.Applications = append(sbom.Applications, *app)
	}
}

// addOrphanPkgs adds orphan packages.
// Orphan packages are packages that are not related to any components.
func (m *Decoder) addOrphanPkgs(sbom *types.SBOM) error {
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
		return xerrors.Errorf("multiple types of OS packages in SBOM are not supported (%q)", maps.Keys(osPkgMap))
	}

	// Add OS packages only when OS is detected.
	for _, pkgs := range osPkgMap {
		if sbom.Metadata.OS == nil || !sbom.Metadata.OS.Detected() {
			log.Logger.Warn("Ignore the OS package as no OS is detected.")
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
			Type:      pkgType,
			Libraries: pkgs,
		})
	}
	return nil
}

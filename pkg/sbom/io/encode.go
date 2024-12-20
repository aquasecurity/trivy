package io

import (
	"fmt"
	"slices"
	"strconv"

	"github.com/google/uuid"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/fanal/artifact"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Encoder struct {
	bom        *core.BOM
	opts       core.Options
	components map[uuid.UUID]*core.Component
}

func NewEncoder(opts core.Options) *Encoder {
	return &Encoder{opts: opts}
}

func (e *Encoder) Encode(report types.Report) (*core.BOM, error) {
	if report.BOM != nil {
		e.components = report.BOM.Components()
	}
	// Metadata component
	root, err := e.rootComponent(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to create root component: %w", err)
	}

	e.bom = core.NewBOM(e.opts)
	if report.BOM != nil {
		e.bom.SerialNumber = report.BOM.SerialNumber
		e.bom.Version = report.BOM.Version
	}
	e.bom.AddComponent(root)

	for _, result := range report.Results {
		e.encodeResult(root, report.Metadata, result)
	}

	// Components that do not have their own dependencies MUST be declared as empty elements within the graph.
	if _, ok := e.bom.Relationships()[root.ID()]; !ok {
		e.bom.AddRelationship(root, nil, "")
	}
	return e.bom, nil
}

func (e *Encoder) rootComponent(r types.Report) (*core.Component, error) {
	root := &core.Component{
		Root: true,
		Name: r.ArtifactName,
	}

	props := []core.Property{
		{
			Name:  core.PropertySchemaVersion,
			Value: strconv.Itoa(r.SchemaVersion),
		},
	}

	switch r.ArtifactType {
	case artifact.TypeContainerImage:
		root.Type = core.TypeContainerImage
		props = append(props, core.Property{
			Name:  core.PropertyImageID,
			Value: r.Metadata.ImageID,
		})

		// Save image labels as properties with `Labels:` prefix.
		// e.g. `LABEL vendor="aquasecurity"` => `Labels:vendor` -> `aquasecurity`
		for label, value := range r.Metadata.ImageConfig.Config.Labels {
			props = append(props, core.Property{
				Name:  core.PropertyLabelsPrefix + ":" + label,
				Value: value,
			})
		}

		p, err := purl.New(purl.TypeOCI, r.Metadata, ftypes.Package{})
		if err != nil {
			return nil, xerrors.Errorf("failed to new package url for oci: %w", err)
		}
		if p != nil {
			root.PkgIdentifier.PURL = p.Unwrap()
		}

	case artifact.TypeVM:
		root.Type = core.TypeVM
	case artifact.TypeFilesystem:
		root.Type = core.TypeFilesystem
	case artifact.TypeRepository:
		root.Type = core.TypeRepository
	case artifact.TypeCycloneDX, artifact.TypeSPDX:
		// When we scan SBOM file
		// If SBOM file doesn't contain root component - use filesystem
		if r.BOM != nil && r.BOM.Root() != nil {
			return r.BOM.Root(), nil
		}
		// When we scan a `json` file (meaning a file in `json` format) which was created from the SBOM file.
		// e.g. for use in `convert` mode.
		// See https://github.com/aquasecurity/trivy/issues/6780
		root.Type = core.TypeFilesystem
	}

	if r.Metadata.Size != 0 {
		props = append(props, core.Property{
			Name:  core.PropertySize,
			Value: strconv.FormatInt(r.Metadata.Size, 10),
		})
	}

	for _, d := range r.Metadata.RepoDigests {
		props = append(props, core.Property{
			Name:  core.PropertyRepoDigest,
			Value: d,
		})
	}

	for _, id := range r.Metadata.DiffIDs {
		props = append(props, core.Property{
			Name:  core.PropertyDiffID,
			Value: id,
		})
	}

	for _, tag := range r.Metadata.RepoTags {
		props = append(props, core.Property{
			Name:  core.PropertyRepoTag,
			Value: tag,
		})
	}

	root.Properties = filterProperties(props)

	return root, nil
}

func (e *Encoder) encodeResult(root *core.Component, metadata types.Metadata, result types.Result) {
	if slices.Contains(ftypes.AggregatingTypes, result.Type) {
		// If a package is language-specific package that isn't associated with a lock file,
		// it will be a dependency of a component under "metadata".
		// e.g.
		//   Container component (alpine:3.15) ----------------------- #1
		//     -> Library component (npm package, express-4.17.3) ---- #2
		//     -> Library component (python package, django-4.0.2) --- #2
		//     -> etc.
		// ref. https://cyclonedx.org/use-cases/#inventory

		// Dependency graph from #1 to #2
		e.encodePackages(root, result)
	} else if result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg {
		// If a package is OS package, it will be a dependency of "Operating System" component.
		// e.g.
		//   Container component (alpine:3.15) --------------------- #1
		//     -> Operating System Component (Alpine Linux 3.15) --- #2
		//       -> Library component (bash-4.12) ------------------ #3
		//       -> Library component (vim-8.2)   ------------------ #3
		//       -> etc.
		//
		// Else if a package is language-specific package associated with a lock file,
		// it will be a dependency of "Application" component.
		// e.g.
		//   Container component (alpine:3.15) ------------------------ #1
		//     -> Application component (/app/package-lock.json) ------ #2
		//       -> Library component (npm package, express-4.17.3) --- #3
		//       -> Library component (npm package, lodash-4.17.21) --- #3
		//       -> etc.

		// #2
		appComponent := e.resultComponent(root, result, metadata.OS)

		// #3
		e.encodePackages(appComponent, result)
	}
}

func (e *Encoder) encodePackages(parent *core.Component, result types.Result) {
	// Get dependency parents first
	parents := ftypes.Packages(result.Packages).ParentDeps()

	// Group vulnerabilities by package ID
	vulns := make(map[string][]core.Vulnerability)
	for _, vuln := range result.Vulnerabilities {
		v := e.vulnerability(vuln)
		vulns[vuln.PkgIdentifier.UID] = append(vulns[vuln.PkgIdentifier.UID], v)
	}

	// UID => Package Component
	components := make(map[string]*core.Component, len(result.Packages))
	// PkgID => Package Component
	dependencies := make(map[string]*core.Component, len(result.Packages))
	for i, pkg := range result.Packages {
		pkgID := lo.Ternary(pkg.ID == "", fmt.Sprintf("%s@%s", pkg.Name, pkg.Version), pkg.ID)
		result.Packages[i].ID = pkgID

		// Convert packages to components
		c := e.component(result, pkg)
		components[pkg.Identifier.UID] = c

		// For dependencies: the key "pkgID" might be duplicated in aggregated packages,
		// but it doesn't matter as they don't have "DependsOn".
		dependencies[pkgID] = c

		// Add a component
		e.bom.AddComponent(c)

		// Add vulnerabilities
		if vv := vulns[pkg.Identifier.UID]; vv != nil {
			e.bom.AddVulnerabilities(c, vv)
		}
	}

	// Build a dependency graph between packages
	for _, pkg := range result.Packages {
		c := components[pkg.Identifier.UID]

		// Add a relationship between the parent and the package if needed
		if e.belongToParent(pkg, parents) {
			e.bom.AddRelationship(parent, c, core.RelationshipContains)
		}

		// Add relationships between the package and its dependencies
		for _, dep := range pkg.DependsOn {
			dependsOn, ok := dependencies[dep]
			if !ok {
				continue
			}
			e.bom.AddRelationship(c, dependsOn, core.RelationshipDependsOn)
		}

		// Components that do not have their own dependencies MUST be declared as empty elements within the graph.
		// TODO: Should check if the component has actually no dependencies or the dependency graph is not supported.
		if len(pkg.DependsOn) == 0 {
			e.bom.AddRelationship(c, nil, "")
		}
	}
}

// existedPkgIdentifier tries to look for package identifier (BOM-ref, PURL) by component name and component type
func (e *Encoder) existedPkgIdentifier(name string, componentType core.ComponentType) ftypes.PkgIdentifier {
	for _, c := range e.components {
		if c.Name == name && c.Type == componentType {
			return c.PkgIdentifier
		}
	}
	return ftypes.PkgIdentifier{}
}

func (e *Encoder) resultComponent(root *core.Component, r types.Result, osFound *ftypes.OS) *core.Component {
	component := &core.Component{
		Name: r.Target,
		Properties: []core.Property{
			{
				Name:  core.PropertyType,
				Value: string(r.Type),
			},
			{
				Name:  core.PropertyClass,
				Value: string(r.Class),
			},
		},
	}

	switch r.Class {
	case types.ClassOSPkg:
		if osFound != nil {
			component.Name = string(osFound.Family)
			component.Version = osFound.Name
		}
		component.Type = core.TypeOS
		component.PkgIdentifier = e.existedPkgIdentifier(component.Name, component.Type)
	case types.ClassLangPkg:
		component.Type = core.TypeApplication
		component.PkgIdentifier = e.existedPkgIdentifier(component.Name, component.Type)
	}

	e.bom.AddRelationship(root, component, core.RelationshipContains)
	return component
}

func (*Encoder) component(result types.Result, pkg ftypes.Package) *core.Component {
	name := pkg.Name
	version := utils.FormatVersion(pkg)
	var group string
	// there are cases when we can't build purl
	// e.g. local Go packages
	if pu := pkg.Identifier.PURL; pu != nil {
		version = pu.Version
		for _, q := range pu.Qualifiers {
			if q.Key == "epoch" && q.Value != "0" {
				version = fmt.Sprintf("%s:%s", q.Value, version)
			}
		}

		// Use `group` field for GroupID and `name` for ArtifactID for java files
		// https://github.com/aquasecurity/trivy/issues/4675
		// Use `group` field for npm scopes
		// https://github.com/aquasecurity/trivy/issues/5908
		if pu.Type == packageurl.TypeMaven || pu.Type == packageurl.TypeNPM {
			name = pu.Name
			group = pu.Namespace
		}
	}

	properties := []core.Property{
		{
			Name:  core.PropertyPkgID,
			Value: pkg.ID,
		},
		{
			Name:  core.PropertyPkgType,
			Value: string(result.Type),
		},
		{
			Name:  core.PropertyFilePath,
			Value: pkg.FilePath,
		},
		{
			Name:  core.PropertySrcName,
			Value: pkg.SrcName,
		},
		{
			Name:  core.PropertySrcVersion,
			Value: pkg.SrcVersion,
		},
		{
			Name:  core.PropertySrcRelease,
			Value: pkg.SrcRelease,
		},
		{
			Name:  core.PropertySrcEpoch,
			Value: strconv.Itoa(pkg.SrcEpoch),
		},
		{
			Name:  core.PropertyModularitylabel,
			Value: pkg.Modularitylabel,
		},
		{
			Name:  core.PropertyLayerDigest,
			Value: pkg.Layer.Digest,
		},
		{
			Name:  core.PropertyLayerDiffID,
			Value: pkg.Layer.DiffID,
		},
	}

	var files []core.File
	if pkg.FilePath != "" || pkg.Digest != "" {
		files = append(files, core.File{
			Path:    pkg.FilePath,
			Digests: lo.Ternary(pkg.Digest != "", []digest.Digest{pkg.Digest}, nil),
		})
	}

	// TODO(refactor): simplify the list of conditions
	var srcFile string
	if result.Class == types.ClassLangPkg && !slices.Contains(ftypes.AggregatingTypes, result.Type) {
		srcFile = result.Target
	}

	return &core.Component{
		Type:       core.TypeLibrary,
		Name:       name,
		Group:      group,
		Version:    version,
		SrcName:    pkg.SrcName,
		SrcVersion: utils.FormatSrcVersion(pkg),
		SrcFile:    srcFile,
		PkgIdentifier: ftypes.PkgIdentifier{
			UID:    pkg.Identifier.UID,
			PURL:   pkg.Identifier.PURL,
			BOMRef: pkg.Identifier.BOMRef,
		},
		Supplier:   pkg.Maintainer,
		Licenses:   pkg.Licenses,
		Files:      files,
		Properties: filterProperties(properties),
	}
}

func (*Encoder) vulnerability(vuln types.DetectedVulnerability) core.Vulnerability {
	return core.Vulnerability{
		Vulnerability:    vuln.Vulnerability,
		ID:               vuln.VulnerabilityID,
		PkgName:          vuln.PkgName,
		InstalledVersion: vuln.InstalledVersion,
		FixedVersion:     vuln.FixedVersion,
		PrimaryURL:       vuln.PrimaryURL,
		DataSource:       vuln.DataSource,
	}
}

// belongToParent determines if a package should be directly included in the parent based on its relationship and dependencies.
func (*Encoder) belongToParent(pkg ftypes.Package, parents map[string]ftypes.Packages) bool {
	// Case 1: Relationship: known , DependsOn: known
	//         Packages with no parent are included in the parent
	//         - Relationship:
	//           - Root: true (it doesn't have a parent)
	//           - Workspace: false (it always has a parent)
	//           - Direct:
	//             - Under Root or Workspace: false (it always has a parent)
	//             - No parents: true (e.g., package-lock.json)
	//           - Indirect: false (it always has a parent)
	// Case 2: Relationship: unknown, DependsOn: unknown (e.g., conan lockfile v2)
	//         All packages are included in the parent
	// Case 3: Relationship: known , DependsOn: unknown (e.g., go.mod without $GOPATH)
	//         All packages are included in the parent
	// Case 4: Relationship: unknown, DependsOn: known (e.g., GoBinaries, OS packages)
	//         - Packages with parents: false. These packages are included in the packages from `parents` (e.g. GoBinaries deps and root package).
	//         - Packages without parents: true. These packages are included in the parent (e.g. OS packages without parents).
	return len(parents[pkg.ID]) == 0
}

func filterProperties(props []core.Property) []core.Property {
	return lo.Filter(props, func(property core.Property, _ int) bool {
		return !(property.Value == "" || (property.Name == core.PropertySrcEpoch && property.Value == "0"))
	})
}

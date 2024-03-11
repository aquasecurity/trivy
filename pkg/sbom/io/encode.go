package io

import (
	"fmt"
	"strconv"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Encoder struct {
	bom *core.BOM
}

func NewEncoder() *Encoder {
	return &Encoder{}
}

func (m *Encoder) Encode(report types.Report) (*core.BOM, error) {
	// Metadata component
	root, err := m.rootComponent(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to create root component: %w", err)
	}

	m.bom = core.NewBOM()
	m.bom.AddComponent(root)

	for _, result := range report.Results {
		m.encodeResult(root, report.Metadata, result)
	}

	// Components that do not have their own dependencies MUST be declared as empty elements within the graph.
	if _, ok := m.bom.Relationships()[root.ID()]; !ok {
		m.bom.AddRelationship(root, nil, "")
	}
	return m.bom, nil
}

func (m *Encoder) rootComponent(r types.Report) (*core.Component, error) {
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
	case ftypes.ArtifactContainerImage:
		root.Type = core.TypeContainer
		props = append(props, core.Property{
			Name:  core.PropertyImageID,
			Value: r.Metadata.ImageID,
		})

		p, err := purl.New(purl.TypeOCI, r.Metadata, ftypes.Package{})
		if err != nil {
			return nil, xerrors.Errorf("failed to new package url for oci: %w", err)
		}
		if p != nil {
			root.PkgID.PURL = p.Unwrap()
		}

	case ftypes.ArtifactVM:
		root.Type = core.TypeContainer
	case ftypes.ArtifactFilesystem, ftypes.ArtifactRepository:
		root.Type = core.TypeApplication
	case ftypes.ArtifactCycloneDX:
		return r.BOM.Root(), nil
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

func (m *Encoder) encodeResult(root *core.Component, metadata types.Metadata, result types.Result) {
	if result.Type == ftypes.NodePkg || result.Type == ftypes.PythonPkg ||
		result.Type == ftypes.GemSpec || result.Type == ftypes.Jar || result.Type == ftypes.CondaPkg {
		// If a package is language-specific package that isn't associated with a lock file,
		// it will be a dependency of a component under "metadata".
		// e.g.
		//   Container component (alpine:3.15) ----------------------- #1
		//     -> Library component (npm package, express-4.17.3) ---- #2
		//     -> Library component (python package, django-4.0.2) --- #2
		//     -> etc.
		// ref. https://cyclonedx.org/use-cases/#inventory

		// Dependency graph from #1 to #2
		m.encodePackages(root, result)
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
		appComponent := m.resultComponent(root, result, metadata.OS)

		// #3
		m.encodePackages(appComponent, result)
	}
}

func (m *Encoder) encodePackages(parent *core.Component, result types.Result) {
	// Get dependency parents first
	parents := ftypes.Packages(result.Packages).ParentDeps()

	// Group vulnerabilities by package ID
	vulns := make(map[string][]core.Vulnerability)
	for _, vuln := range result.Vulnerabilities {
		v := m.vulnerability(vuln)
		vulns[v.PkgID] = append(vulns[v.PkgID], v)
	}

	// Convert packages into components and add them to the BOM
	components := make(map[string]*core.Component, len(result.Packages))
	for i, pkg := range result.Packages {
		pkgID := lo.Ternary(pkg.ID == "", fmt.Sprintf("%s@%s", pkg.Name, pkg.Version), pkg.ID)
		result.Packages[i].ID = pkgID

		// Convert packages to components
		c := m.component(result.Type, pkg)
		components[pkgID] = c

		// Add a component
		m.bom.AddComponent(c)

		// Add vulnerabilities
		if vv := vulns[pkgID]; vv != nil {
			m.bom.AddVulnerabilities(c, vv)
		}
	}

	// Build a dependency graph
	for _, pkg := range result.Packages {
		// Skip indirect dependencies
		if pkg.Indirect && len(parents[pkg.ID]) != 0 {
			continue
		}

		directPkg := components[pkg.ID]
		m.bom.AddRelationship(parent, directPkg, core.RelationshipContains)

		for _, dep := range pkg.DependsOn {
			indirectPkg, ok := components[dep]
			if !ok {
				continue
			}
			m.bom.AddRelationship(directPkg, indirectPkg, core.RelationshipDependsOn)
		}

		// Components that do not have their own dependencies MUST be declared as empty elements within the graph.
		// TODO: Should check if the component has actually no dependencies or the dependency graph is not supported.
		if len(pkg.DependsOn) == 0 {
			m.bom.AddRelationship(directPkg, nil, "")
		}
	}
}

func (m *Encoder) resultComponent(root *core.Component, r types.Result, osFound *ftypes.OS) *core.Component {
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
	case types.ClassLangPkg:
		component.Type = core.TypeApplication
	}

	m.bom.AddRelationship(root, component, core.RelationshipContains)
	return component
}

func (*Encoder) component(pkgType ftypes.TargetType, pkg ftypes.Package) *core.Component {
	name := pkg.Name
	version := pkg.Version
	var group string
	// there are cases when we can't build purl
	// e.g. local Go packages
	if pu := pkg.Identifier.PURL; pu != nil {
		version = pu.Version
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
			Value: string(pkgType),
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
			Path: pkg.FilePath,
			Hash: pkg.Digest,
		})
	}

	return &core.Component{
		Type:    core.TypeLibrary,
		Name:    name,
		Group:   group,
		Version: version,
		PkgID: core.PkgID{
			PURL: pkg.Identifier.PURL,
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
		PkgID:            lo.Ternary(vuln.PkgID == "", fmt.Sprintf("%s@%s", vuln.PkgName, vuln.InstalledVersion), vuln.PkgID),
		PkgName:          vuln.PkgName,
		InstalledVersion: vuln.InstalledVersion,
		FixedVersion:     vuln.FixedVersion,
		PrimaryURL:       vuln.PrimaryURL,
		DataSource:       vuln.DataSource,
	}
}

func filterProperties(props []core.Property) []core.Property {
	return lo.Filter(props, func(property core.Property, _ int) bool {
		return !(property.Value == "" || (property.Name == core.PropertySrcEpoch && property.Value == "0"))
	})
}

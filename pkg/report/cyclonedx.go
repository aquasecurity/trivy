package report

import (
	"io"
	"strconv"
	"strings"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/app"
)

const (
	Namespace               = "aquasecurity:trivy:"
	PropertyType            = Namespace + "Type"
	PropertyClass           = Namespace + "Class"
	PropertySchemaVersion   = Namespace + "SchemaVersion"
	PropertySize            = Namespace + "Size"
	PropertyDigest          = Namespace + "Digest"
	PropertyTag             = Namespace + "Tag"
	PropertyRelease         = Namespace + "release"
	PropertyEpoch           = Namespace + "epoch"
	PropertyArch            = Namespace + "arch"
	PropertySrcName         = Namespace + "src_name"
	PropertySrcVersion      = Namespace + "src_version"
	PropertySrcRelease      = Namespace + "src_release"
	PropertySrcEpoch        = Namespace + "src_epoch"
	PropertyModularitylabel = Namespace + "modularitylabel"
	PropertyFilePath        = Namespace + "file_path"
)

// CycloneDXWriter implements result Writer
type CycloneDXWriter struct {
	Output io.Writer
}

// Write writes the results in CycloneDX format
func (cw CycloneDXWriter) Write(report Report) error {
	bom, err := ConvertToBom(report)
	if err != nil {
		return xerrors.Errorf("failed to convert to bom: %w", err)
	}
	if err = cdx.NewBOMEncoder(cw.Output, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		return xerrors.Errorf("failed to encode bom: %w", err)
	}

	return nil
}

func ConvertToBom(r Report) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: Now().UTC().Format(time.RFC3339Nano),
		Tools: &[]cdx.Tool{
			{
				Vendor:  app.Vendor,
				Name:    app.Name,
				Version: app.Version,
			},
		},
		Component: reportToComponent(r),
	}

	libraryUniqMap := map[string]struct{}{}

	componets := []cdx.Component{}
	dependencies := []cdx.Dependency{}
	for _, result := range r.Results {
		resultComponent := resultToComponent(result, r.Metadata.OS)
		componets = append(componets, resultComponent)

		componentDependencies := []cdx.Dependency{}
		for _, pkg := range result.Packages {
			pkgComponent, err := pkgToComponent(result.Type, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to package to component: %w", err)
			}

			if _, ok := libraryUniqMap[pkgComponent.PackageURL]; !ok {
				componets = append(componets, pkgComponent)
			}
			componentDependencies = append(componentDependencies, cdx.Dependency{Ref: pkgComponent.BOMRef})
		}

		if len(componentDependencies) != 0 {
			dependencies = append(dependencies,
				cdx.Dependency{Ref: resultComponent.BOMRef, Dependencies: &componentDependencies},
			)
		}
	}

	bom.Components = &componets
	if len(dependencies) != 0 {
		bom.Dependencies = &dependencies
	}

	return bom, nil
}

func pkgToComponent(t string, pkg types.Package) (cdx.Component, error) {
	purl := NewPackageURL(t, pkg)
	version := pkg.Version
	if pkg.Release != "" {
		version = strings.Join([]string{pkg.Version, pkg.Release}, "-")
	}
	properties := parseProperties(pkg)
	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.Name,
		Version:    version,
		BOMRef:     purl,
		PackageURL: purl,
		Properties: &properties,
	}

	if pkg.License != "" {
		component.Licenses = &cdx.Licenses{
			cdx.LicenseChoice{Expression: pkg.License},
		}
	}

	return component, nil
}

func parseProperties(pkg types.Package) []cdx.Property {
	properties := []cdx.Property{}
	if pkg.FilePath != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyFilePath,
				Value: pkg.FilePath,
			},
		)
	}
	if pkg.Release != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyRelease,
				Value: pkg.Release,
			},
		)
	}
	if pkg.Epoch != 0 {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyEpoch,
				Value: strconv.Itoa(pkg.Epoch),
			},
		)
	}
	if pkg.Arch != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyArch,
				Value: pkg.Arch,
			},
		)
	}
	if pkg.SrcRelease != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertySrcRelease,
				Value: pkg.SrcRelease,
			},
		)
	}
	if pkg.SrcEpoch != 0 {
		properties = append(properties,
			cdx.Property{
				Name:  PropertySrcEpoch,
				Value: strconv.Itoa(pkg.SrcEpoch),
			},
		)
	}
	if pkg.Modularitylabel != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyModularitylabel,
				Value: pkg.Modularitylabel,
			},
		)
	}
	if pkg.SrcName != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertySrcName,
				Value: pkg.SrcName,
			},
		)
	}
	return properties
}

func NewPackageURL(t string, pkg types.Package) string {
	name := strings.ReplaceAll(pkg.Name, ":", "/")
	index := strings.LastIndex(name, "/")

	namespace := ""
	pkgName := name
	if index != -1 {
		namespace = name[:index]
		pkgName = name[index+1:]
	}
	purl := packageurl.NewPackageURL(t, namespace, pkgName, pkg.Version, parseQualifier(pkg), "")

	return purl.String()
}

func parseQualifier(pkg types.Package) packageurl.Qualifiers {
	qualifiers := packageurl.Qualifiers{}
	if pkg.Release != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "release",
			Value: pkg.Release,
		})
	}
	if pkg.Epoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "epoch",
			Value: strconv.Itoa(pkg.Epoch),
		})
	}
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	if pkg.SrcName != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_name",
			Value: pkg.SrcName,
		})
	}
	if pkg.SrcVersion != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_version",
			Value: pkg.SrcVersion,
		})
	}
	if pkg.SrcRelease != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_release",
			Value: pkg.SrcRelease,
		})
	}
	if pkg.SrcEpoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_epoch",
			Value: strconv.Itoa(pkg.SrcEpoch),
		})
	}
	if pkg.Modularitylabel != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "modularitylabel",
			Value: pkg.Modularitylabel,
		})
	}
	if pkg.FilePath != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "file_path",
			Value: pkg.FilePath,
		})
	}
	return qualifiers
}

func reportToComponent(r Report) *cdx.Component {
	component := &cdx.Component{
		Name: r.ArtifactName,
	}

	properties := []cdx.Property{
		{
			Name:  PropertySchemaVersion,
			Value: strconv.Itoa(r.SchemaVersion),
		},
	}

	if r.Metadata.Size != 0 {
		properties = append(properties,
			cdx.Property{
				Name:  PropertySize,
				Value: strconv.FormatInt(r.Metadata.Size, 10),
			},
		)
	}

	switch r.ArtifactType {
	case types.ArtifactContainerImage:
		component.Type = cdx.ComponentTypeContainer
	case types.ArtifactFilesystem, types.ArtifactRemoteRepository:
		component.Type = cdx.ComponentTypeApplication
	}

	if r.Metadata.OS != nil {
		component.Version = r.Metadata.OS.Name
		for _, d := range r.Metadata.RepoDigests {
			properties = append(properties, cdx.Property{
				Name:  PropertyDigest,
				Value: d,
			})
		}
		for _, t := range r.Metadata.RepoTags {
			properties = append(properties, cdx.Property{
				Name:  PropertyTag,
				Value: t,
			})
		}
		component.Properties = &properties
	}

	return component
}

func resultToComponent(r Result, osFound *types.OS) cdx.Component {
	component := cdx.Component{
		Name:   r.Target,
		BOMRef: r.Target,
		Properties: &[]cdx.Property{
			{
				Name:  PropertyType,
				Value: r.Type,
			},
			{
				Name:  PropertyClass,
				Value: string(r.Class),
			},
		},
	}

	switch r.Class {
	case ClassOSPkg:
		if osFound != nil {
			component.Name = osFound.Family
			component.Version = osFound.Name
		}
		component.Type = cdx.ComponentTypeOS
	case ClassLangPkg:
		component.Type = cdx.ComponentTypeApplication
	case ClassConfig:
		// TODO: Config support
		component.Type = cdx.ComponentTypeFile
	}

	return component
}

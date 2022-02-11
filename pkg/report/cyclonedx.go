package report

import (
	"io"
	"strconv"
	"time"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/google/uuid"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	Namespace               = "aquasecurity:trivy:"
	PropertyType            = Namespace + "Type"
	PropertyClass           = Namespace + "Class"
	PropertySchemaVersion   = Namespace + "SchemaVersion"
	PropertySize            = Namespace + "Size"
	PropertyDigest          = Namespace + "Digest"
	PropertyTag             = Namespace + "Tag"
	PropertyRelease         = Namespace + "Release"
	PropertyEpoch           = Namespace + "Epoch"
	PropertyArch            = Namespace + "Arch"
	PropertySrcName         = Namespace + "SrcName"
	PropertySrcVersion      = Namespace + "SrcVersion"
	PropertySrcRelease      = Namespace + "SrcRelease"
	PropertySrcEpoch        = Namespace + "SrcEpoch"
	PropertyModularitylabel = Namespace + "Modularitylabel"
	PropertyFilePath        = Namespace + "FilePath"
	PropertyLayerDigest     = Namespace + "LayerDigest"
	PropertyLayerDiffID     = Namespace + "LayerDiffID"
)

// CycloneDXWriter implements result Writer
type CycloneDXWriter struct {
	Output  io.Writer
	Version string
	Format  cdx.BOMFileFormat
}

var New = uuid.New

// Write writes the results in CycloneDX format
func (cw CycloneDXWriter) Write(report types.Report) error {
	bom, err := ConvertToBom(report, cw.Version)
	if err != nil {
		return xerrors.Errorf("failed to convert bom: %w", err)
	}

	if err := cdx.NewBOMEncoder(cw.Output, cw.Format).Encode(bom); err != nil {
		return xerrors.Errorf("failed to encode bom: %w", err)
	}

	return nil
}

func ConvertToBom(r types.Report, version string) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	bom.SerialNumber = New().URN()
	metadataComponent, err := reportToComponent(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse metadata component: %w", err)
	}
	bom.Metadata = &cdx.Metadata{
		Timestamp: Now().UTC().Format(time.RFC3339Nano),
		Tools: &[]cdx.Tool{
			{
				Vendor:  "aquasecurity",
				Name:    "trivy",
				Version: version,
			},
		},
		Component: metadataComponent,
	}

	libraryUniqMap := map[string]struct{}{}

	var components []cdx.Component
	var dependencies []cdx.Dependency
	var metadataDependencies []cdx.Dependency
	for _, result := range r.Results {
		resultComponent := resultToComponent(result, r.Metadata.OS)
		components = append(components, resultComponent)

		var componentDependencies []cdx.Dependency
		for _, pkg := range result.Packages {
			pkgComponent, err := pkgToComponent(result.Type, r.Metadata, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse pkg: %w", err)
			}

			if _, ok := libraryUniqMap[pkgComponent.PackageURL]; !ok {
				libraryUniqMap[pkgComponent.PackageURL] = struct{}{}
				components = append(components, pkgComponent)
			}

			if pkg.FilePath != "" {
				metadataDependencies = append(metadataDependencies, cdx.Dependency{Ref: pkgComponent.BOMRef})
			} else {
				componentDependencies = append(componentDependencies, cdx.Dependency{Ref: pkgComponent.BOMRef})
			}
		}

		dependencies = append(dependencies,
			cdx.Dependency{Ref: resultComponent.BOMRef, Dependencies: &componentDependencies},
		)
		metadataDependencies = append(metadataDependencies, cdx.Dependency{Ref: resultComponent.BOMRef})
	}
	dependencies = append(dependencies,
		cdx.Dependency{Ref: bom.Metadata.Component.BOMRef, Dependencies: &metadataDependencies},
	)

	bom.Components = &components
	if len(dependencies) != 0 {
		bom.Dependencies = &dependencies
	}

	return bom, nil
}

func pkgToComponent(t string, meta types.Metadata, pkg ftypes.Package) (cdx.Component, error) {
	pu, err := purl.NewPackageURL(t, meta, pkg)
	if err != nil {
		return cdx.Component{}, xerrors.Errorf("failed to new package purl: %w", err)
	}
	properties := parseProperties(pkg)
	component := cdx.Component{
		Type:       cdx.ComponentTypeLibrary,
		Name:       pkg.Name,
		Version:    pu.Version,
		BOMRef:     pu.ToString(),
		PackageURL: pu.ToString(),
		Properties: &properties,
	}

	if pkg.License != "" {
		component.Licenses = &cdx.Licenses{
			cdx.LicenseChoice{Expression: pkg.License},
		}
	}

	return component, nil
}

func reportToComponent(r types.Report) (*cdx.Component, error) {
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
	case ftypes.ArtifactContainerImage:
		component.Type = cdx.ComponentTypeContainer
		p, err := purl.NewPackageURL(purl.TypeOCI, r.Metadata, ftypes.Package{})
		if err != nil {
			return nil, xerrors.Errorf("failed to new package url for oci: %w", err)
		}

		component.BOMRef = p.ToString()
		component.PackageURL = p.ToString()
	case ftypes.ArtifactFilesystem, ftypes.ArtifactRemoteRepository:
		component.Type = cdx.ComponentTypeApplication
		component.BOMRef = New().String()
	}
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

	return component, nil
}

func resultToComponent(r types.Result, osFound *ftypes.OS) cdx.Component {
	component := cdx.Component{
		Name: r.Target,
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
	case types.ClassOSPkg:
		component.BOMRef = New().String()
		if osFound != nil {
			component.Name = osFound.Family
			component.Version = osFound.Name
		}
		component.Type = cdx.ComponentTypeOS
	case types.ClassLangPkg:
		component.BOMRef = New().String()
		component.Type = cdx.ComponentTypeApplication
	case types.ClassConfig:
		// TODO: Config support
		component.BOMRef = New().String()
		component.Type = cdx.ComponentTypeFile
	}

	return component
}

func parseProperties(pkg ftypes.Package) []cdx.Property {
	var properties []cdx.Property
	if pkg.FilePath != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyFilePath,
				Value: pkg.FilePath,
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
	if pkg.SrcName != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertySrcName,
				Value: pkg.SrcName,
			},
		)
	}
	if pkg.SrcVersion != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertySrcVersion,
				Value: pkg.SrcVersion,
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
	if pkg.Layer.Digest != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyLayerDigest,
				Value: pkg.Layer.Digest,
			},
		)
	}
	if pkg.Layer.DiffID != "" {
		properties = append(properties,
			cdx.Property{
				Name:  PropertyLayerDiffID,
				Value: pkg.Layer.DiffID,
			},
		)
	}

	return properties
}

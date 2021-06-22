package report

import (
	"fmt"
	"io"
	"strings"
	"time"

	fos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"golang.org/x/xerrors"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/gorilla/schema"
)

// CycloneDXWriter implements result Writer
type CycloneDXWriter struct {
	Output io.Writer
}

// Write writes the results in CycloneDX format
func (cw CycloneDXWriter) Write(report Report) error {
	bom, err := convertToBom(report)
	if err != nil {
		return xerrors.Errorf("failed to convert to bom: %w", err)
	}
	if err = cdx.NewBOMEncoder(cw.Output, cdx.BOMFileFormatJSON).Encode(bom); err != nil {
		return xerrors.Errorf("failed to encode bom: %w", err)
	}

	return nil
}

func convertToBom(r Report) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	bom.Metadata = &cdx.Metadata{
		Timestamp: time.Now().Format(time.RFC3339),
		Tools: &[]cdx.Tool{
			{
				Vendor:  "aquasecurity",
				Name:    "Trivy",
				Version: "0.17.1",
			},
		},
		Component: &cdx.Component{
			Type:   TypeToComponent(string(r.ArtifactType)),
			Name:   r.ArtifactName,
			BOMRef: r.ArtifactID,
			// TODO: Support properties for cdx 1.3, add repo tags and digests
		},
	}

	libraryMap := map[string]struct{}{}
	componets := []cdx.Component{}
	dependencies := []cdx.Dependency{}
	for _, result := range r.Results {
		component := &cdx.Component{
			Type:   TypeToComponent(result.Type),
			Name:   result.Target,
			BOMRef: result.Target,
		}
		componets = append(componets, *component)

		componentDependencies := []cdx.Dependency{}
		for _, pkg := range result.Packages {
			purl, err := NewPackageUrl(result.Type, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to new package url: %w", err)
			}
			libComponent := &cdx.Component{
				Type:       cdx.ComponentTypeLibrary,
				Name:       pkg.Name,
				Version:    pkg.Version,
				PackageURL: purl,
				BOMRef:     purl,
			}
			if _, ok := libraryMap[libComponent.BOMRef]; !ok {
				componets = append(componets, *libComponent)
			}
			componentDependencies = append(componentDependencies, cdx.Dependency{Ref: libComponent.BOMRef})
		}
		dependencies = append(dependencies, cdx.Dependency{Ref: component.BOMRef, Dependencies: &componentDependencies})
	}
	bom.Components = &componets
	bom.Dependencies = &dependencies

	return bom, nil
}

func NewPackageUrl(t string, pkg types.Package) (string, error) {
	purl := fmt.Sprintf("pkg:%s/%s@%s", t, pkg.Name, pkg.Version)
	qualifiersMap := map[string][]string{}
	if err := schema.NewEncoder().Encode(pkg, qualifiersMap); err != nil {
		return "", xerrors.Errorf("failed to encode qualifiers: %w", err)
	}

	qualifiers := []string{}
	for k, v := range qualifiersMap {
		qualifiers = append(qualifiers, fmt.Sprintf("%s=%s", k, v))
	}
	if len(qualifiers) != 0 {
		purl = fmt.Sprintf("%s?%s", purl, strings.Join(qualifiers, "&"))
	}

	return purl, nil
}

func TypeToComponent(t string) (c cdx.ComponentType) {
	switch t {
	case string(types.ArtifactContainerImage):
		return cdx.ComponentTypeContainer
	case string(types.ArtifactFilesystem), string(types.ArtifactRemoteRepository):
		return cdx.ComponentTypeApplication
	case fos.RedHat, fos.Debian, fos.Ubuntu, fos.CentOS, fos.Fedora, fos.Amazon,
		fos.Oracle, fos.Windows, fos.OpenSUSE, fos.OpenSUSELeap, fos.OpenSUSETumbleweed,
		fos.SLES, fos.Photon, fos.Alpine:
		return cdx.ComponentTypeOS
	default:
		return cdx.ComponentTypeFile
	}
}

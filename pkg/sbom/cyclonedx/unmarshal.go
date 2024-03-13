package cyclonedx

import (
	"bytes"
	"errors"
	"io"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"go.uber.org/zap"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

var (
	ErrUnsupportedType = errors.New("unsupported type")
)

type BOM struct {
	*core.BOM
}

func DecodeJSON(r io.Reader) (*cdx.BOM, error) {
	bom := cdx.NewBOM()
	decoder := cdx.NewBOMDecoder(r, cdx.BOMFileFormatJSON)
	if err := decoder.Decode(bom); err != nil {
		return nil, xerrors.Errorf("CycloneDX decode error: %w", err)
	}
	return bom, nil
}

func (b *BOM) UnmarshalJSON(data []byte) error {
	log.Logger.Debug("Unmarshalling CycloneDX JSON...")
	if b.BOM == nil {
		b.BOM = core.NewBOM(core.Options{GenerateBOMRef: true})
	}

	cdxBOM, err := DecodeJSON(bytes.NewReader(data))
	if err != nil {
		return xerrors.Errorf("CycloneDX decode error: %w", err)
	}

	if !IsTrivySBOM(cdxBOM) {
		log.Logger.Warnf("Third-party SBOM may lead to inaccurate vulnerability detection")
		log.Logger.Warnf("Recommend using Trivy to generate SBOMs")
	}

	if err = b.parseBOM(cdxBOM); err != nil {
		return xerrors.Errorf("failed to parse sbom: %w", err)
	}

	// Store the original metadata
	b.BOM.SerialNumber = cdxBOM.SerialNumber
	b.BOM.Version = cdxBOM.Version

	return nil
}

func (b *BOM) parseBOM(bom *cdx.BOM) error {
	// Convert all CycloneDX components into Trivy components
	components := b.parseComponents(bom.Components)

	// Convert the metadata component into Trivy component
	mComponent, err := b.parseMetadataComponent(bom)
	if err != nil {
		return xerrors.Errorf("failed to parse root component: %w", err)
	} else if mComponent != nil {
		components[mComponent.PkgID.BOMRef] = mComponent
	}

	// Parse dependencies and build relationships
	for _, dep := range lo.FromPtr(bom.Dependencies) {
		ref, ok := components[dep.Ref]
		if !ok {
			continue
		}
		for _, depRef := range lo.FromPtr(dep.Dependencies) {
			dependency, ok := components[depRef]
			if !ok {
				continue
			}
			b.BOM.AddRelationship(ref, dependency, core.RelationshipDependsOn)
		}
	}
	return nil
}

func (b *BOM) parseMetadataComponent(bom *cdx.BOM) (*core.Component, error) {
	if bom.Metadata == nil || bom.Metadata.Component == nil {
		return nil, nil
	}
	root, err := b.parseComponent(*bom.Metadata.Component)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse metadata component: %w", err)
	}
	root.Root = true
	b.BOM.AddComponent(root)
	return root, nil
}

func (b *BOM) parseComponents(cdxComponents *[]cdx.Component) map[string]*core.Component {
	components := make(map[string]*core.Component)
	for _, component := range lo.FromPtr(cdxComponents) {
		c, err := b.parseComponent(component)
		if errors.Is(err, ErrUnsupportedType) {
			log.Logger.Infow("Skipping the component with the unsupported type",
				zap.String("bom-ref", component.BOMRef), zap.String("type", string(component.Type)))
			continue
		} else if err != nil {
			log.Logger.Warnw("Failed to parse component: %s", zap.Error(err))
			continue
		}

		b.BOM.AddComponent(c)
		components[component.BOMRef] = c
	}
	return components
}

func (b *BOM) parseComponent(c cdx.Component) (*core.Component, error) {
	componentType, err := b.unmarshalType(c.Type)
	if err != nil {
		return nil, xerrors.Errorf("failed to unmarshal component type: %w", err)
	}

	// Parse PURL
	var purl packageurl.PackageURL
	if c.PackageURL != "" {
		purl, err = packageurl.FromString(c.PackageURL)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse PURL: %w", err)
		}
	}

	component := &core.Component{
		Type:     componentType,
		Name:     c.Name,
		Group:    c.Group,
		Version:  c.Version,
		Licenses: b.unmarshalLicenses(c.Licenses),
		Files: []core.File{
			{
				Digests: b.unmarshalHashes(c.Hashes),
			},
		},
		PkgID: core.PkgID{
			PURL:   &purl,
			BOMRef: c.BOMRef,
		},
		Supplier:   b.unmarshalSupplier(c.Supplier),
		Properties: b.unmarshalProperties(c.Properties),
	}

	return component, nil
}

func (b *BOM) unmarshalType(t cdx.ComponentType) (core.ComponentType, error) {
	var ctype core.ComponentType
	switch t {
	case cdx.ComponentTypeContainer:
		ctype = core.TypeContainerImage
	case cdx.ComponentTypeApplication:
		ctype = core.TypeApplication
	case cdx.ComponentTypeLibrary:
		ctype = core.TypeLibrary
	case cdx.ComponentTypeOS:
		ctype = core.TypeOS
	case cdx.ComponentTypePlatform:
		ctype = core.TypePlatform
	default:
		return "", ErrUnsupportedType
	}
	return ctype, nil
}

// parsePackageLicenses checks all supported license fields and returns a list of licenses.
// https://cyclonedx.org/docs/1.5/json/#components_items_licenses
func (b *BOM) unmarshalLicenses(l *cdx.Licenses) []string {
	var licenses []string
	for _, license := range lo.FromPtr(l) {
		if license.License != nil {
			// Trivy uses `Name` field to marshal licenses
			if license.License.Name != "" {
				licenses = append(licenses, license.License.Name)
				continue
			}

			if license.License.ID != "" {
				licenses = append(licenses, license.License.ID)
				continue
			}
		}

		if license.Expression != "" {
			licenses = append(licenses, license.Expression)
			continue
		}

	}
	return licenses
}

func (b *BOM) unmarshalHashes(hashes *[]cdx.Hash) []digest.Digest {
	var digests []digest.Digest
	for _, h := range lo.FromPtr(hashes) {
		var alg digest.Algorithm
		switch h.Algorithm {
		case cdx.HashAlgoSHA1:
			alg = digest.SHA1
		case cdx.HashAlgoSHA256:
			alg = digest.SHA256
		case cdx.HashAlgoMD5:
			alg = digest.MD5
		default:
			log.Logger.Warnf("Unsupported hash algorithm: %s", h.Algorithm)
		}
		digests = append(digests, digest.NewDigestFromString(alg, h.Value))
	}
	return digests
}

func (b *BOM) unmarshalSupplier(supplier *cdx.OrganizationalEntity) string {
	if supplier == nil {
		return ""
	}
	return supplier.Name
}

func (b *BOM) unmarshalProperties(properties *[]cdx.Property) []core.Property {
	var props []core.Property
	for _, p := range lo.FromPtr(properties) {
		props = append(props, core.Property{
			Name:  strings.TrimPrefix(p.Name, Namespace),
			Value: p.Value,
		})
	}
	return props
}

func IsTrivySBOM(c *cdx.BOM) bool {
	if c == nil || c.Metadata == nil || c.Metadata.Tools == nil {
		return false
	}

	for _, component := range lo.FromPtr(c.Metadata.Tools.Components) {
		if component.Group == ToolVendor && component.Name == ToolName {
			return true
		}
	}

	// Metadata.Tools array is deprecated (as of CycloneDX v1.5). We check this field for backward compatibility.
	// cf. https://github.com/CycloneDX/cyclonedx-go/blob/b9654ae9b4705645152d20eb9872b5f3d73eac49/cyclonedx.go#L988
	for _, tool := range lo.FromPtr(c.Metadata.Tools.Tools) {
		if tool.Vendor == ToolVendor && tool.Name == ToolName {
			return true
		}
	}
	return false
}

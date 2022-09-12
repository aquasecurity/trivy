package spdx

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/spdx/tools-golang/spdx"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	SPDXVersion         = "SPDX-2.2"
	DataLicense         = "CC0-1.0"
	SPDXIdentifier      = "DOCUMENT"
	DocumentNamespace   = "http://aquasecurity.github.io/trivy"
	CreatorOrganization = "aquasecurity"
	CreatorTool         = "trivy"
)

const (
	CategoryPackageManager = "PACKAGE-MANAGER"
	RefTypePurl            = "purl"

	PropertySchemaVersion = "SchemaVersion"

	// Image properties
	PropertySize       = "Size"
	PropertyImageID    = "ImageID"
	PropertyRepoDigest = "RepoDigest"
	PropertyDiffID     = "DiffID"
	PropertyRepoTag    = "RepoTag"

	// Package properties
	PropertyLayerDiffID = "LayerDiffID"
	PropertyLayerDigest = "LayerDigest"

	RelationShipContains  = "CONTAINS"
	RelationShipDescribe  = "DESCRIBE"
	RelationShipDependsOn = "DEPENDS_ON"

	ElementOperatingSystem = "OperatingSystem"
	ElementApplication     = "Application"
)

var (
	SourcePackagePrefix = "built package from"
)

type Marshaler struct {
	format  spdx.Document2_1
	clock   clock.Clock
	newUUID newUUID
	hasher  Hash
}

type Hash func(v interface{}, format hashstructure.Format, opts *hashstructure.HashOptions) (uint64, error)

type newUUID func() uuid.UUID

type marshalOption func(*Marshaler)

func WithClock(clock clock.Clock) marshalOption {
	return func(opts *Marshaler) {
		opts.clock = clock
	}
}

func WithNewUUID(newUUID newUUID) marshalOption {
	return func(opts *Marshaler) {
		opts.newUUID = newUUID
	}
}

func WithHasher(hasher Hash) marshalOption {
	return func(opts *Marshaler) {
		opts.hasher = hasher
	}
}

func NewMarshaler(opts ...marshalOption) *Marshaler {
	m := &Marshaler{
		format:  spdx.Document2_1{},
		clock:   clock.RealClock{},
		newUUID: uuid.New,
		hasher:  hashstructure.Hash,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func relationShip(refA, refB spdx.ElementID, operator string) *spdx.Relationship2_2 {
	ref := spdx.Relationship2_2{
		RefA:         spdx.MakeDocElementID("", string(refA)),
		RefB:         spdx.MakeDocElementID("", string(refB)),
		Relationship: operator,
	}
	return &ref
}

func (m *Marshaler) Marshal(r types.Report) (*spdx.Document2_2, error) {
	var relationShips []*spdx.Relationship2_2
	packages := make(map[spdx.ElementID]*spdx.Package2_2)

	reportPackage, err := m.reportPackage(r)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse report package: %w", err)
	}
	packages[reportPackage.PackageSPDXIdentifier] = &reportPackage
	relationShips = append(relationShips,
		relationShip(SPDXIdentifier, reportPackage.PackageSPDXIdentifier, RelationShipDescribe),
	)

	for _, result := range r.Results {
		var (
			parentIdentifier spdx.ElementID
			parentPackage    spdx.Package2_2
			err              error

			operator = RelationShipContains
		)

		switch result.Class {
		case types.ClassOSPkg:
			if r.Metadata.OS == nil {
				continue
			}
			parentPackage, err = m.operatingSystemPackage(r.Metadata.OS)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse operating system package: %w", err)
			}
			parentIdentifier = parentPackage.PackageSPDXIdentifier
		case types.ClassLangPkg:
			parentPackage, err = m.applicationPackage(result.Target, result.Type)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse application package: %w", err)
			}
			parentIdentifier = parentPackage.PackageSPDXIdentifier
		}

		packages[parentIdentifier] = &parentPackage
		relationShips = append(relationShips,
			relationShip(reportPackage.PackageSPDXIdentifier, parentIdentifier, operator),
		)
		operator = RelationShipDependsOn

		for _, pkg := range result.Packages {
			spdxPackage, err := m.pkgToSpdxPackage(result.Type, result.Class, r.Metadata, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse os package: %w", err)
			}
			var file spdx.File2_2
			if pkg.FilePath != "" {
				pkgID, err := getPackageID(m.hasher, pkg.FilePath)
				if err != nil {
					return nil, xerrors.Errorf("failed to get %s package ID: %w", pkg.FilePath, err)
				}
				file = spdx.File2_2{
					FileSPDXIdentifier: spdx.ElementID(fmt.Sprintf("File-%s", pkgID)),
					FileName:           pkg.FilePath,
				}
				spdxPackage.Files = map[spdx.ElementID]*spdx.File2_2{
					file.FileSPDXIdentifier: &file,
				}
			}
			pkg, ok := packages[spdxPackage.PackageSPDXIdentifier]
			if ok {
				if file.FileSPDXIdentifier != "" {
					pkg.Files[file.FileSPDXIdentifier] = &file
				}
			} else {
				packages[spdxPackage.PackageSPDXIdentifier] = &spdxPackage
			}
			relationShips = append(relationShips,
				relationShip(parentIdentifier, spdxPackage.PackageSPDXIdentifier, operator),
			)
		}
	}

	return &spdx.Document2_2{
		CreationInfo: &spdx.CreationInfo2_2{
			SPDXVersion:          SPDXVersion,
			DataLicense:          DataLicense,
			SPDXIdentifier:       SPDXIdentifier,
			DocumentName:         r.ArtifactName,
			DocumentNamespace:    getDocumentNamespace(r, m),
			CreatorOrganizations: []string{CreatorOrganization},
			CreatorTools:         []string{CreatorTool},
			Created:              m.clock.Now().UTC().Format(time.RFC3339Nano),
		},
		Packages:      packages,
		Relationships: relationShips,
	}, nil
}

func (m *Marshaler) operatingSystemPackage(osFound *ftypes.OS) (spdx.Package2_2, error) {
	var spdxPackage spdx.Package2_2
	pkgID, err := getPackageID(m.hasher, osFound)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get os metadata package ID: %w", err)
	}
	spdxPackage.PackageSPDXIdentifier = spdx.ElementID(fmt.Sprintf("%s-%s", ElementOperatingSystem, pkgID))
	spdxPackage.PackageName = osFound.Family
	spdxPackage.PackageVersion = osFound.Name
	return spdxPackage, nil
}

func (m *Marshaler) reportPackage(r types.Report) (spdx.Package2_2, error) {
	var spdxPackage spdx.Package2_2

	attributionTexts := []string{attributionText(PropertySchemaVersion, strconv.Itoa(r.SchemaVersion))}
	if r.Metadata.OS != nil {
		p, err := purl.NewPackageURL(purl.TypeOCI, r.Metadata, ftypes.Package{})
		if err != nil {
			return spdx.Package2_2{}, xerrors.Errorf("failed to new package url for oci: %w", err)
		}
		if p.Type != "" {
			spdxPackage.PackageExternalReferences = packageExternalReference(p.ToString())
		}
		attributionTexts = appendAttributionText(attributionTexts, PropertyImageID, r.Metadata.ImageID)
	}

	if r.Metadata.Size != 0 {
		attributionTexts = appendAttributionText(attributionTexts, PropertySize, strconv.FormatInt(r.Metadata.Size, 10))
	}

	for _, d := range r.Metadata.RepoDigests {
		attributionTexts = appendAttributionText(attributionTexts, PropertyRepoDigest, d)
	}
	for _, d := range r.Metadata.DiffIDs {
		attributionTexts = appendAttributionText(attributionTexts, PropertyDiffID, d)
	}
	for _, t := range r.Metadata.RepoTags {
		attributionTexts = appendAttributionText(attributionTexts, PropertyRepoTag, t)
	}

	spdxPackage.PackageAttributionTexts = attributionTexts
	pkgID, err := getPackageID(m.hasher, fmt.Sprintf("%s-%s", r.ArtifactName, r.ArtifactType))
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", err)
	}
	spdxPackage.PackageSPDXIdentifier = spdx.ElementID(fmt.Sprintf("%s-%s", camelCase(string(r.ArtifactType)), pkgID))
	spdxPackage.PackageName = r.ArtifactName

	return spdxPackage, nil
}

func (m *Marshaler) applicationPackage(target, typ string) (spdx.Package2_2, error) {
	var spdxPackage spdx.Package2_2

	spdxPackage.PackageName = target
	spdxPackage.PackageVersion = typ
	pkgID, err := getPackageID(m.hasher, fmt.Sprintf("%s-%s", target, typ))
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", target, err)
	}
	spdxPackage.PackageSPDXIdentifier = spdx.ElementID(fmt.Sprintf("%s-%s", ElementApplication, pkgID))

	return spdxPackage, nil
}

func (m *Marshaler) pkgToSpdxPackage(t string, class types.ResultClass, metadata types.Metadata, pkg ftypes.Package) (spdx.Package2_2, error) {
	var spdxPackage spdx.Package2_2
	license := getLicense(pkg)

	pkgID, err := getPackageID(m.hasher, pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", pkg.Name, err)
	}

	spdxPackage.PackageSPDXIdentifier = spdx.ElementID(fmt.Sprintf("Package-%s", pkgID))
	spdxPackage.PackageName = pkg.Name
	spdxPackage.PackageVersion = pkg.Version

	if class == types.ClassOSPkg {
		spdxPackage.PackageSourceInfo = fmt.Sprintf("%s: %s %s", SourcePackagePrefix, pkg.Name, utils.FormatSrcVersion(pkg))
	}

	packageURL, err := purl.NewPackageURL(t, metadata, pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to parse purl (%s): %w", pkg.Name, err)
	}
	spdxPackage.PackageExternalReferences = packageExternalReference(packageURL.String())

	// The Declared License is what the authors of a project believe govern the package
	spdxPackage.PackageLicenseConcluded = license

	// The Concluded License field is the license the SPDX file creator believes governs the package
	spdxPackage.PackageLicenseDeclared = license

	spdxPackage.PackageAttributionTexts = appendAttributionText(spdxPackage.PackageAttributionTexts, PropertyLayerDigest, pkg.Layer.Digest)
	spdxPackage.PackageAttributionTexts = appendAttributionText(spdxPackage.PackageAttributionTexts, PropertyLayerDiffID, pkg.Layer.DiffID)

	return spdxPackage, nil
}
func appendAttributionText(attributionTexts []string, key, value string) []string {
	if value == "" {
		return attributionTexts
	}
	return append(attributionTexts, attributionText(key, value))
}

func attributionText(key, value string) string {
	return fmt.Sprintf("%s: %s", key, value)
}

func packageExternalReference(packageURL string) []*spdx.PackageExternalReference2_2 {
	return []*spdx.PackageExternalReference2_2{
		{
			Category: CategoryPackageManager,
			RefType:  RefTypePurl,
			Locator:  packageURL,
		},
	}
}

func getLicense(p ftypes.Package) string {
	if len(p.Licenses) == 0 {
		return "NONE"
	}

	return strings.Join(p.Licenses, ", ")
}

func getDocumentNamespace(r types.Report, m *Marshaler) string {
	return fmt.Sprintf("%s/%s/%s-%s",
		DocumentNamespace,
		string(r.ArtifactType),
		r.ArtifactName,
		m.newUUID().String(),
	)
}

func getPackageID(h Hash, v interface{}) (string, error) {
	f, err := h(v, hashstructure.FormatV2, &hashstructure.HashOptions{
		ZeroNil:      true,
		SlicesAsSets: true,
	})
	if err != nil {
		return "", xerrors.Errorf("could not build package ID for %+v: %w", v, err)
	}

	return fmt.Sprintf("%x", f), nil
}

func camelCase(inputUnderScoreStr string) (camelCase string) {
	isToUpper := false
	for k, v := range inputUnderScoreStr {
		if k == 0 {
			camelCase = strings.ToUpper(string(inputUnderScoreStr[0]))
		} else {
			if isToUpper {
				camelCase += strings.ToUpper(string(v))
				isToUpper = false
			} else {
				if v == '_' {
					isToUpper = true
				} else {
					camelCase += string(v)
				}
			}
		}
	}
	return
}

package spdx

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/mitchellh/hashstructure/v2"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
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
	noneField           = "NONE"
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
	PropertyPkgID       = "PkgID"
	PropertyLayerDiffID = "LayerDiffID"
	PropertyLayerDigest = "LayerDigest"

	RelationShipContains  = "CONTAINS"
	RelationShipDescribe  = "DESCRIBES"
	RelationShipDependsOn = "DEPENDS_ON"

	ElementOperatingSystem = "OperatingSystem"
	ElementApplication     = "Application"
	ElementPackage         = "Package"
	ElementFile            = "File"
)

var (
	SourcePackagePrefix = "built package from"
)

type Marshaler struct {
	format     spdx.Document2_1
	clock      clock.Clock
	newUUID    newUUID
	hasher     Hash
	appVersion string // Trivy version. It needed for `creator` field
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

func NewMarshaler(version string, opts ...marshalOption) *Marshaler {
	m := &Marshaler{
		format:     spdx.Document2_1{},
		clock:      clock.RealClock{},
		newUUID:    uuid.New,
		hasher:     hashstructure.Hash,
		appVersion: version,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func (m *Marshaler) Marshal(r types.Report) (*spdx.Document2_2, error) {
	var relationShips []*spdx.Relationship2_2
	packages := make(map[spdx.ElementID]*spdx.Package2_2)
	pkgDownloadLocation := getPackageDownloadLocation(r.ArtifactType, r.ArtifactName)

	// Root package contains OS, OS packages, language-specific packages and so on.
	rootPkg, err := m.rootPackage(r, pkgDownloadLocation)
	if err != nil {
		return nil, xerrors.Errorf("failed to generate a root package: %w", err)
	}
	packages[rootPkg.PackageSPDXIdentifier] = rootPkg
	relationShips = append(relationShips,
		relationShip(SPDXIdentifier, rootPkg.PackageSPDXIdentifier, RelationShipDescribe),
	)

	for _, result := range r.Results {
		parentPackage, err := m.resultToSpdxPackage(result, r.Metadata.OS, pkgDownloadLocation)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse result: %w", err)
		}
		packages[parentPackage.PackageSPDXIdentifier] = &parentPackage
		relationShips = append(relationShips,
			relationShip(rootPkg.PackageSPDXIdentifier, parentPackage.PackageSPDXIdentifier, RelationShipContains),
		)

		for _, pkg := range result.Packages {
			spdxPackage, err := m.pkgToSpdxPackage(result.Type, pkgDownloadLocation, result.Class, r.Metadata, pkg)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse package: %w", err)
			}
			packages[spdxPackage.PackageSPDXIdentifier] = &spdxPackage
			relationShips = append(relationShips,
				relationShip(parentPackage.PackageSPDXIdentifier, spdxPackage.PackageSPDXIdentifier, RelationShipContains),
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
			CreatorTools:         []string{fmt.Sprintf("%s-%s", CreatorTool, m.appVersion)},
			Created:              m.clock.Now().UTC().Format(time.RFC3339),
		},
		Packages:      packages,
		Relationships: relationShips,
	}, nil
}

func (m *Marshaler) resultToSpdxPackage(result types.Result, os *ftypes.OS, pkgDownloadLocation string) (spdx.Package2_2, error) {
	switch result.Class {
	case types.ClassOSPkg:
		osPkg, err := m.osPackage(os, pkgDownloadLocation)
		if err != nil {
			return spdx.Package2_2{}, xerrors.Errorf("failed to parse operating system package: %w", err)
		}
		return osPkg, nil
	case types.ClassLangPkg:
		langPkg, err := m.langPackage(result.Target, result.Type, pkgDownloadLocation)
		if err != nil {
			return spdx.Package2_2{}, xerrors.Errorf("failed to parse application package: %w", err)
		}
		return langPkg, nil
	default:
		// unsupported packages
		return spdx.Package2_2{}, nil
	}
}

func (m *Marshaler) parseFile(filePath string, digest digest.Digest) (spdx.File2_2, error) {
	pkgID, err := calcPkgID(m.hasher, filePath)
	if err != nil {
		return spdx.File2_2{}, xerrors.Errorf("failed to get %s package ID: %w", filePath, err)
	}
	file := spdx.File2_2{
		FileSPDXIdentifier: spdx.ElementID(fmt.Sprintf("File-%s", pkgID)),
		FileName:           filePath,
		FileChecksums:      digestToSpdxFileChecksum(digest),
	}
	return file, nil
}

func (m *Marshaler) rootPackage(r types.Report, pkgDownloadLocation string) (*spdx.Package2_2, error) {
	var externalReferences []*spdx.PackageExternalReference2_2
	attributionTexts := []string{attributionText(PropertySchemaVersion, strconv.Itoa(r.SchemaVersion))}

	// When the target is a container image, add PURL to the external references of the root package.
	if p, err := purl.NewPackageURL(purl.TypeOCI, r.Metadata, ftypes.Package{}); err != nil {
		return nil, xerrors.Errorf("failed to new package url for oci: %w", err)
	} else if p.Type != "" {
		externalReferences = append(externalReferences, purlExternalReference(p.ToString()))
	}

	if r.Metadata.ImageID != "" {
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

	pkgID, err := calcPkgID(m.hasher, fmt.Sprintf("%s-%s", r.ArtifactName, r.ArtifactType))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s package ID: %w", err)
	}

	return &spdx.Package2_2{
		PackageName:               r.ArtifactName,
		PackageSPDXIdentifier:     elementID(camelCase(string(r.ArtifactType)), pkgID),
		PackageDownloadLocation:   pkgDownloadLocation,
		PackageAttributionTexts:   attributionTexts,
		PackageExternalReferences: externalReferences,
	}, nil
}

func (m *Marshaler) osPackage(osFound *ftypes.OS, pkgDownloadLocation string) (spdx.Package2_2, error) {
	if osFound == nil {
		return spdx.Package2_2{}, nil
	}

	pkgID, err := calcPkgID(m.hasher, osFound)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get os metadata package ID: %w", err)
	}

	return spdx.Package2_2{
		PackageName:             osFound.Family,
		PackageVersion:          osFound.Name,
		PackageSPDXIdentifier:   elementID(ElementOperatingSystem, pkgID),
		PackageDownloadLocation: pkgDownloadLocation,
	}, nil
}

func (m *Marshaler) langPackage(target, appType, pkgDownloadLocation string) (spdx.Package2_2, error) {
	pkgID, err := calcPkgID(m.hasher, fmt.Sprintf("%s-%s", target, appType))
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", target, err)
	}

	return spdx.Package2_2{
		PackageName:             appType,
		PackageSourceInfo:       target, // TODO: Files seems better
		PackageSPDXIdentifier:   elementID(ElementApplication, pkgID),
		PackageDownloadLocation: pkgDownloadLocation,
	}, nil
}

func (m *Marshaler) pkgToSpdxPackage(t, pkgDownloadLocation string, class types.ResultClass, metadata types.Metadata, pkg ftypes.Package) (spdx.Package2_2, error) {
	license := GetLicense(pkg)

	pkgID, err := calcPkgID(m.hasher, pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to get %s package ID: %w", pkg.Name, err)
	}

	var pkgSrcInfo string
	if class == types.ClassOSPkg {
		pkgSrcInfo = fmt.Sprintf("%s: %s %s", SourcePackagePrefix, pkg.SrcName, utils.FormatSrcVersion(pkg))
	}

	packageURL, err := purl.NewPackageURL(t, metadata, pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("failed to parse purl (%s): %w", pkg.Name, err)
	}
	pkgExtRefs := []*spdx.PackageExternalReference2_2{purlExternalReference(packageURL.String())}

	var attrTexts []string
	attrTexts = appendAttributionText(attrTexts, PropertyPkgID, pkg.ID)
	attrTexts = appendAttributionText(attrTexts, PropertyLayerDigest, pkg.Layer.Digest)
	attrTexts = appendAttributionText(attrTexts, PropertyLayerDiffID, pkg.Layer.DiffID)

	files, err := m.pkgFiles(pkg)
	if err != nil {
		return spdx.Package2_2{}, xerrors.Errorf("package file error: %w", err)
	}

	return spdx.Package2_2{
		PackageName:             pkg.Name,
		PackageVersion:          utils.FormatVersion(pkg),
		PackageSPDXIdentifier:   elementID(ElementPackage, pkgID),
		PackageDownloadLocation: pkgDownloadLocation,
		PackageSourceInfo:       pkgSrcInfo,

		// The Declared License is what the authors of a project believe govern the package
		PackageLicenseConcluded: license,

		// The Concluded License field is the license the SPDX file creator believes governs the package
		PackageLicenseDeclared: license,

		PackageExternalReferences: pkgExtRefs,
		PackageAttributionTexts:   attrTexts,
		Files:                     files,
	}, nil
}

func (m *Marshaler) pkgFiles(pkg ftypes.Package) (map[spdx.ElementID]*spdx.File2_2, error) {
	if pkg.FilePath == "" {
		return nil, nil
	}

	file, err := m.parseFile(pkg.FilePath, pkg.Digest)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse file: %w")
	}
	return map[spdx.ElementID]*spdx.File2_2{
		file.FileSPDXIdentifier: &file,
	}, nil
}

func elementID(elementType, pkgID string) spdx.ElementID {
	return spdx.ElementID(fmt.Sprintf("%s-%s", elementType, pkgID))
}

func relationShip(refA, refB spdx.ElementID, operator string) *spdx.Relationship2_2 {
	ref := spdx.Relationship2_2{
		RefA:         spdx.MakeDocElementID("", string(refA)),
		RefB:         spdx.MakeDocElementID("", string(refB)),
		Relationship: operator,
	}
	return &ref
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

func purlExternalReference(packageURL string) *spdx.PackageExternalReference2_2 {
	return &spdx.PackageExternalReference2_2{
		Category: CategoryPackageManager,
		RefType:  RefTypePurl,
		Locator:  packageURL,
	}
}

func GetLicense(p ftypes.Package) string {
	if len(p.Licenses) == 0 {
		return noneField
	}

	license := strings.Join(lo.Map(p.Licenses, func(license string, index int) string {
		// e.g. GPL-3.0-with-autoconf-exception
		license = strings.ReplaceAll(license, "-with-", " WITH ")
		license = strings.ReplaceAll(license, "-WITH-", " WITH ")

		return fmt.Sprintf("(%s)", license)
	}), " AND ")
	s, err := expression.Normalize(license, licensing.Normalize, expression.NormalizeForSPDX)
	if err != nil {
		// Not fail on the invalid license
		log.Logger.Warnf("Unable to marshal SPDX licenses %q", license)
		return ""
	}
	return s
}

func getDocumentNamespace(r types.Report, m *Marshaler) string {
	return fmt.Sprintf("%s/%s/%s-%s",
		DocumentNamespace,
		string(r.ArtifactType),
		strings.ReplaceAll(strings.ReplaceAll(r.ArtifactName, "https://", ""), "http://", ""), // remove http(s):// prefix when scanning repos
		m.newUUID().String(),
	)
}

func calcPkgID(h Hash, v interface{}) (string, error) {
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

func getPackageDownloadLocation(t ftypes.ArtifactType, artifactName string) string {
	location := noneField
	// this field is used for git/mercurial/subversion/bazaar:
	// https://spdx.github.io/spdx-spec/v2.2.2/package-information/#77-package-download-location-field
	if t == ftypes.ArtifactRemoteRepository {
		// Trivy currently only supports git repositories. Format examples:
		// git+https://git.myproject.org/MyProject.git
		// git+http://git.myproject.org/MyProject
		location = fmt.Sprintf("git+%s", artifactName)
	}
	return location
}

func digestToSpdxFileChecksum(d digest.Digest) map[spdx.ChecksumAlgorithm]spdx.Checksum {
	if d == "" {
		return nil
	}

	var alg spdx.ChecksumAlgorithm
	switch d.Algorithm() {
	case digest.SHA1:
		alg = spdx.SHA1
	case digest.SHA256:
		alg = spdx.SHA256
	default:
		return nil
	}

	return map[spdx.ChecksumAlgorithm]spdx.Checksum{
		alg: {
			Algorithm: alg,
			Value:     d.Encoded(),
		},
	}
}

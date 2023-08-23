package spdx

import (
	"fmt"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"golang.org/x/exp/maps"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/digest"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

const (
	DocumentSPDXIdentifier = "DOCUMENT"
	DocumentNamespace      = "http://aquasecurity.github.io/trivy"
	CreatorOrganization    = "aquasecurity"
	CreatorTool            = "trivy"
	noneField              = "NONE"
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
	// Package Purpose fields
	PackagePurposeOS          = "OPERATING-SYSTEM"
	PackagePurposeContainer   = "CONTAINER"
	PackagePurposeSource      = "SOURCE"
	PackagePurposeApplication = "APPLICATION"
	PackagePurposeLibrary     = "LIBRARY"

	PackageSupplierNoAssertion  = "NOASSERTION"
	PackageSupplierOrganization = "Organization"

	RelationShipContains  = common.TypeRelationshipContains
	RelationShipDescribe  = common.TypeRelationshipDescribe
	RelationShipDependsOn = common.TypeRelationshipDependsOn

	ElementOperatingSystem = "OperatingSystem"
	ElementApplication     = "Application"
	ElementPackage         = "Package"
	ElementFile            = "File"
)

var (
	SourcePackagePrefix = "built package from"
)

type Marshaler struct {
	format     spdx.Document
	hasher     Hash
	appVersion string // Trivy version. It needed for `creator` field
}

type Hash func(v interface{}, format hashstructure.Format, opts *hashstructure.HashOptions) (uint64, error)

type marshalOption func(*Marshaler)

func WithHasher(hasher Hash) marshalOption {
	return func(opts *Marshaler) {
		opts.hasher = hasher
	}
}

func NewMarshaler(version string, opts ...marshalOption) *Marshaler {
	m := &Marshaler{
		format:     spdx.Document{},
		hasher:     hashstructure.Hash,
		appVersion: version,
	}

	for _, opt := range opts {
		opt(m)
	}

	return m
}

func (m *Marshaler) Marshal(r types.Report) (*spdx.Document, error) {
	var relationShips []*spdx.Relationship
	packages := make(map[spdx.ElementID]*spdx.Package)
	pkgDownloadLocation := getPackageDownloadLocation(r.ArtifactType, r.ArtifactName)

	// Root package contains OS, OS packages, language-specific packages and so on.
	rootPkg, err := m.rootPackage(r, pkgDownloadLocation)
	if err != nil {
		return nil, xerrors.Errorf("failed to generate a root package: %w", err)
	}
	packages[rootPkg.PackageSPDXIdentifier] = rootPkg
	relationShips = append(relationShips,
		relationShip(DocumentSPDXIdentifier, rootPkg.PackageSPDXIdentifier, RelationShipDescribe),
	)

	var spdxFiles []*spdx.File

	for _, result := range r.Results {
		if len(result.Packages) == 0 {
			continue
		}
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
			files, err := m.pkgFiles(pkg)
			if err != nil {
				return nil, xerrors.Errorf("package file error: %w", err)
			}
			spdxFiles = append(spdxFiles, files...)
			for _, file := range files {
				relationShips = append(relationShips,
					relationShip(spdxPackage.PackageSPDXIdentifier, file.FileSPDXIdentifier, RelationShipContains),
				)
			}
		}
	}

	return &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    DocumentSPDXIdentifier,
		DocumentName:      r.ArtifactName,
		DocumentNamespace: getDocumentNamespace(r, m),
		CreationInfo: &spdx.CreationInfo{
			Creators: []common.Creator{
				{
					Creator:     CreatorOrganization,
					CreatorType: "Organization",
				},
				{
					Creator:     fmt.Sprintf("%s-%s", CreatorTool, m.appVersion),
					CreatorType: "Tool",
				},
			},
			Created: clock.Now().UTC().Format(time.RFC3339),
		},
		Packages:      toPackages(packages),
		Relationships: relationShips,
		Files:         spdxFiles,
	}, nil
}

func toPackages(packages map[spdx.ElementID]*spdx.Package) []*spdx.Package {
	ret := maps.Values(packages)
	sort.Slice(ret, func(i, j int) bool {
		if ret[i].PackageName != ret[j].PackageName {
			return ret[i].PackageName < ret[j].PackageName
		}
		return ret[i].PackageSPDXIdentifier < ret[j].PackageSPDXIdentifier
	})
	return ret
}

func (m *Marshaler) resultToSpdxPackage(result types.Result, os *ftypes.OS, pkgDownloadLocation string) (spdx.Package, error) {
	switch result.Class {
	case types.ClassOSPkg:
		osPkg, err := m.osPackage(os, pkgDownloadLocation)
		if err != nil {
			return spdx.Package{}, xerrors.Errorf("failed to parse operating system package: %w", err)
		}
		return osPkg, nil
	case types.ClassLangPkg:
		langPkg, err := m.langPackage(result.Target, result.Type, pkgDownloadLocation)
		if err != nil {
			return spdx.Package{}, xerrors.Errorf("failed to parse application package: %w", err)
		}
		return langPkg, nil
	default:
		// unsupported packages
		return spdx.Package{}, nil
	}
}

func (m *Marshaler) parseFile(filePath string, digest digest.Digest) (spdx.File, error) {
	pkgID, err := calcPkgID(m.hasher, filePath)
	if err != nil {
		return spdx.File{}, xerrors.Errorf("failed to get %s package ID: %w", filePath, err)
	}
	file := spdx.File{
		FileSPDXIdentifier: spdx.ElementID(fmt.Sprintf("File-%s", pkgID)),
		FileName:           filePath,
		Checksums:          digestToSpdxFileChecksum(digest),
	}
	return file, nil
}

func (m *Marshaler) rootPackage(r types.Report, pkgDownloadLocation string) (*spdx.Package, error) {
	var externalReferences []*spdx.PackageExternalReference
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
		return nil, xerrors.Errorf("failed to get %s package ID: %w", pkgID, err)
	}

	pkgPurpose := PackagePurposeSource
	if r.ArtifactType == ftypes.ArtifactContainerImage {
		pkgPurpose = PackagePurposeContainer
	}

	return &spdx.Package{
		PackageName:               r.ArtifactName,
		PackageSPDXIdentifier:     elementID(camelCase(string(r.ArtifactType)), pkgID),
		PackageDownloadLocation:   pkgDownloadLocation,
		PackageAttributionTexts:   attributionTexts,
		PackageExternalReferences: externalReferences,
		PrimaryPackagePurpose:     pkgPurpose,
	}, nil
}

func (m *Marshaler) osPackage(osFound *ftypes.OS, pkgDownloadLocation string) (spdx.Package, error) {
	if osFound == nil {
		return spdx.Package{}, nil
	}

	pkgID, err := calcPkgID(m.hasher, osFound)
	if err != nil {
		return spdx.Package{}, xerrors.Errorf("failed to get os metadata package ID: %w", err)
	}

	return spdx.Package{
		PackageName:             osFound.Family,
		PackageVersion:          osFound.Name,
		PackageSPDXIdentifier:   elementID(ElementOperatingSystem, pkgID),
		PackageDownloadLocation: pkgDownloadLocation,
		PrimaryPackagePurpose:   PackagePurposeOS,
	}, nil
}

func (m *Marshaler) langPackage(target, appType, pkgDownloadLocation string) (spdx.Package, error) {
	pkgID, err := calcPkgID(m.hasher, fmt.Sprintf("%s-%s", target, appType))
	if err != nil {
		return spdx.Package{}, xerrors.Errorf("failed to get %s package ID: %w", target, err)
	}

	return spdx.Package{
		PackageName:             appType,
		PackageSourceInfo:       target, // TODO: Files seems better
		PackageSPDXIdentifier:   elementID(ElementApplication, pkgID),
		PackageDownloadLocation: pkgDownloadLocation,
		PrimaryPackagePurpose:   PackagePurposeApplication,
	}, nil
}

func (m *Marshaler) pkgToSpdxPackage(t, pkgDownloadLocation string, class types.ResultClass, metadata types.Metadata, pkg ftypes.Package) (spdx.Package, error) {
	license := GetLicense(pkg)

	pkgID, err := calcPkgID(m.hasher, pkg)
	if err != nil {
		return spdx.Package{}, xerrors.Errorf("failed to get %s package ID: %w", pkg.Name, err)
	}

	var pkgSrcInfo string
	if class == types.ClassOSPkg && pkg.SrcName != "" {
		pkgSrcInfo = fmt.Sprintf("%s: %s %s", SourcePackagePrefix, pkg.SrcName, utils.FormatSrcVersion(pkg))
	}

	packageURL, err := purl.NewPackageURL(t, metadata, pkg)
	if err != nil {
		return spdx.Package{}, xerrors.Errorf("failed to parse purl (%s): %w", pkg.Name, err)
	}
	pkgExtRefs := []*spdx.PackageExternalReference{purlExternalReference(packageURL.String())}

	var attrTexts []string
	attrTexts = appendAttributionText(attrTexts, PropertyPkgID, pkg.ID)
	attrTexts = appendAttributionText(attrTexts, PropertyLayerDigest, pkg.Layer.Digest)
	attrTexts = appendAttributionText(attrTexts, PropertyLayerDiffID, pkg.Layer.DiffID)

	supplier := &spdx.Supplier{Supplier: PackageSupplierNoAssertion}
	if pkg.Maintainer != "" {
		supplier = &spdx.Supplier{
			SupplierType: PackageSupplierOrganization, // Always use "Organization" at the moment as it is difficult to distinguish between "Person" or "Organization".
			Supplier:     pkg.Maintainer,
		}
	}

	var checksum []spdx.Checksum
	if pkg.Digest != "" && class == types.ClassOSPkg {
		checksum = digestToSpdxFileChecksum(pkg.Digest)
	}

	return spdx.Package{
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
		PrimaryPackagePurpose:     PackagePurposeLibrary,
		PackageSupplier:           supplier,
		PackageChecksums:          checksum,
	}, nil
}

func (m *Marshaler) pkgFiles(pkg ftypes.Package) ([]*spdx.File, error) {
	if pkg.FilePath == "" {
		return nil, nil
	}

	file, err := m.parseFile(pkg.FilePath, pkg.Digest)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse file: %w", err)
	}
	return []*spdx.File{
		&file,
	}, nil
}

func elementID(elementType, pkgID string) spdx.ElementID {
	return spdx.ElementID(fmt.Sprintf("%s-%s", elementType, pkgID))
}

func relationShip(refA, refB spdx.ElementID, operator string) *spdx.Relationship {
	ref := spdx.Relationship{
		RefA:         common.MakeDocElementID("", string(refA)),
		RefB:         common.MakeDocElementID("", string(refB)),
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

func purlExternalReference(packageURL string) *spdx.PackageExternalReference {
	return &spdx.PackageExternalReference{
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
		uuid.New().String(),
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
	if t == ftypes.ArtifactRepository {
		// Trivy currently only supports git repositories. Format examples:
		// git+https://git.myproject.org/MyProject.git
		// git+http://git.myproject.org/MyProject
		location = fmt.Sprintf("git+%s", artifactName)
	}
	return location
}

func digestToSpdxFileChecksum(d digest.Digest) []common.Checksum {
	if d == "" {
		return nil
	}

	var alg spdx.ChecksumAlgorithm
	switch d.Algorithm() {
	case digest.SHA1:
		alg = spdx.SHA1
	case digest.SHA256:
		alg = spdx.SHA256
	case digest.MD5:
		alg = spdx.MD5
	default:
		return nil
	}

	return []spdx.Checksum{
		{
			Algorithm: alg,
			Value:     d.Encoded(),
		},
	}
}

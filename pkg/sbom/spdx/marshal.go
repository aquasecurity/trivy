package spdx

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/mitchellh/hashstructure/v2"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	spdxutils "github.com/spdx/tools-golang/utils"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/clock"
	"github.com/aquasecurity/trivy/pkg/digest"
	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	sbomio "github.com/aquasecurity/trivy/pkg/sbom/io"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/aquasecurity/trivy/pkg/uuid"
)

const (
	DocumentSPDXIdentifier = "DOCUMENT"
	DocumentNamespace      = "http://aquasecurity.github.io/trivy"
	CreatorOrganization    = "aquasecurity"
	CreatorTool            = "trivy"
	noneField              = "NONE"
	noAssertionField       = "NOASSERTION"
)

const (
	CategoryPackageManager = "PACKAGE-MANAGER"
	RefTypePurl            = "purl"

	// Package Purpose fields
	PackagePurposeOS          = "OPERATING-SYSTEM"
	PackagePurposeContainer   = "CONTAINER"
	PackagePurposeSource      = "SOURCE"
	PackagePurposeApplication = "APPLICATION"
	PackagePurposeLibrary     = "LIBRARY"

	PackageSupplierNoAssertion  = "NOASSERTION"
	PackageSupplierOrganization = "Organization"

	PackageAnnotatorToolField = "Tool"

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
	SourceFilePrefix    = "package found in"
)

// duplicateProperties contains a list of properties contained in other fields.
var duplicateProperties = []string{
	// `SourceInfo` contains SrcName and SrcVersion (it contains PropertySrcRelease and PropertySrcEpoch)
	core.PropertySrcName,
	core.PropertySrcRelease,
	core.PropertySrcEpoch,
	core.PropertySrcVersion,
	// `File` contains filePath.
	core.PropertyFilePath,
}

type Marshaler struct {
	format     spdx.Document
	hasher     Hash
	appVersion string // Trivy version. It needed for `creator` field
}

type Hash func(v any, format hashstructure.Format, opts *hashstructure.HashOptions) (uint64, error)

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

func (m *Marshaler) MarshalReport(ctx context.Context, report types.Report) (*spdx.Document, error) {
	// Convert into an intermediate representation
	bom, err := sbomio.NewEncoder(core.Options{}).Encode(report)
	if err != nil {
		return nil, xerrors.Errorf("failed to marshal report: %w", err)
	}

	return m.Marshal(ctx, bom)
}

func (m *Marshaler) Marshal(ctx context.Context, bom *core.BOM) (*spdx.Document, error) {
	var (
		relationShips []*spdx.Relationship
		packages      []*spdx.Package
	)

	// Lock time to use same time for all spdx fields
	timeNow := clock.Now(ctx).UTC().Format(time.RFC3339)

	root := bom.Root()
	pkgDownloadLocation := m.packageDownloadLocation(root)

	// Component ID => SPDX ID
	packageIDs := make(map[uuid.UUID]spdx.ElementID)

	// Root package contains OS, OS packages, language-specific packages and so on.
	rootPkg, err := m.rootSPDXPackage(root, timeNow, pkgDownloadLocation)
	if err != nil {
		return nil, xerrors.Errorf("failed to generate a root package: %w", err)
	}
	packages = append(packages, rootPkg)
	relationShips = append(relationShips,
		m.spdxRelationShip(DocumentSPDXIdentifier, rootPkg.PackageSPDXIdentifier, RelationShipDescribe),
	)
	packageIDs[root.ID()] = rootPkg.PackageSPDXIdentifier

	var files []*spdx.File
	for _, c := range bom.Components() {
		if c.Root {
			continue
		}
		spdxPackage, err := m.spdxPackage(c, timeNow, pkgDownloadLocation)
		if err != nil {
			return nil, xerrors.Errorf("spdx package error: %w", err)
		}

		// Add advisories for package
		// cf. https://spdx.github.io/spdx-spec/v2.3/how-to-use/#k1-including-security-information-in-a-spdx-document
		if vulns, ok := bom.Vulnerabilities()[c.ID()]; ok {
			for _, v := range vulns {
				spdxPackage.PackageExternalReferences = append(spdxPackage.PackageExternalReferences, m.advisoryExternalReference(v.PrimaryURL))
			}
		}

		packages = append(packages, &spdxPackage)
		packageIDs[c.ID()] = spdxPackage.PackageSPDXIdentifier

		spdxFiles, err := m.spdxFiles(c)
		if err != nil {
			return nil, xerrors.Errorf("spdx files error: %w", err)
		} else if len(spdxFiles) == 0 {
			continue
		}

		files = append(files, spdxFiles...)
		for _, file := range spdxFiles {
			relationShips = append(relationShips,
				m.spdxRelationShip(spdxPackage.PackageSPDXIdentifier, file.FileSPDXIdentifier, RelationShipContains),
			)
		}
		verificationCode, err := spdxutils.GetVerificationCode(spdxFiles, "")
		if err != nil {
			return nil, xerrors.Errorf("package verification error: %w", err)
		}
		spdxPackage.FilesAnalyzed = true
		spdxPackage.PackageVerificationCode = &verificationCode
	}

	for id, rels := range bom.Relationships() {
		for _, rel := range rels {
			refA, ok := packageIDs[id]
			if !ok {
				continue
			}
			refB, ok := packageIDs[rel.Dependency]
			if !ok {
				continue
			}
			relationShips = append(relationShips, m.spdxRelationShip(refA, refB, m.spdxRelationshipType(rel.Type)))
		}
	}

	sortPackages(packages)
	sortRelationships(relationShips)
	sortFiles(files)

	return &spdx.Document{
		SPDXVersion:       spdx.Version,
		DataLicense:       spdx.DataLicense,
		SPDXIdentifier:    DocumentSPDXIdentifier,
		DocumentName:      root.Name,
		DocumentNamespace: getDocumentNamespace(root),
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
			Created: timeNow,
		},
		Packages:      packages,
		Relationships: relationShips,
		Files:         files,
	}, nil
}

func (m *Marshaler) packageDownloadLocation(root *core.Component) string {
	location := noneField
	// this field is used for git/mercurial/subversion/bazaar:
	// https://spdx.github.io/spdx-spec/v2.2.2/package-information/#77-package-download-location-field
	if root.Type == core.TypeRepository {
		// Trivy currently only supports git repositories. Format examples:
		// git+https://git.myproject.org/MyProject.git
		// git+http://git.myproject.org/MyProject
		location = fmt.Sprintf("git+%s", root.Name)
	}
	return location
}

func (m *Marshaler) rootSPDXPackage(root *core.Component, timeNow, pkgDownloadLocation string) (*spdx.Package, error) {
	var externalReferences []*spdx.PackageExternalReference
	// When the target is a container image, add PURL to the external references of the root package.
	if root.PkgIdentifier.PURL != nil {
		externalReferences = append(externalReferences, m.purlExternalReference(root.PkgIdentifier.PURL.String()))
	}

	pkgID, err := calcPkgID(m.hasher, fmt.Sprintf("%s-%s", root.Name, root.Type))
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s package ID: %w", pkgID, err)
	}

	pkgPurpose := PackagePurposeSource
	if root.Type == core.TypeContainerImage {
		pkgPurpose = PackagePurposeContainer
	}

	return &spdx.Package{
		PackageName:               root.Name,
		PackageSPDXIdentifier:     elementID(camelCase(string(root.Type)), pkgID),
		PackageDownloadLocation:   pkgDownloadLocation,
		Annotations:               m.spdxAnnotations(root, timeNow),
		PackageExternalReferences: externalReferences,
		PrimaryPackagePurpose:     pkgPurpose,
	}, nil
}

func (m *Marshaler) appendAnnotation(annotations []spdx.Annotation, timeNow, key, value string) []spdx.Annotation {
	if value == "" {
		return annotations
	}
	return append(annotations, spdx.Annotation{
		AnnotationDate: timeNow,
		AnnotationType: spdx.CategoryOther,
		Annotator: spdx.Annotator{
			Annotator:     fmt.Sprintf("%s-%s", CreatorTool, m.appVersion),
			AnnotatorType: PackageAnnotatorToolField,
		},
		AnnotationComment: fmt.Sprintf("%s: %s", key, value),
	})
}

func (m *Marshaler) purlExternalReference(packageURL string) *spdx.PackageExternalReference {
	return &spdx.PackageExternalReference{
		Category: CategoryPackageManager,
		RefType:  RefTypePurl,
		Locator:  packageURL,
	}
}

func (m *Marshaler) advisoryExternalReference(primaryURL string) *spdx.PackageExternalReference {
	return &spdx.PackageExternalReference{
		Category: common.CategorySecurity,
		RefType:  common.TypeSecurityAdvisory,
		Locator:  primaryURL,
	}
}

func (m *Marshaler) spdxPackage(c *core.Component, timeNow, pkgDownloadLocation string) (spdx.Package, error) {
	pkgID, err := calcPkgID(m.hasher, c)
	if err != nil {
		return spdx.Package{}, xerrors.Errorf("failed to get os metadata package ID: %w", err)
	}

	var elementType, purpose, license, sourceInfo string
	var supplier *spdx.Supplier
	switch c.Type {
	case core.TypeOS:
		elementType = ElementOperatingSystem
		purpose = PackagePurposeOS
	case core.TypeApplication:
		elementType = ElementApplication
		purpose = PackagePurposeApplication
	case core.TypeLibrary:
		elementType = ElementPackage
		purpose = PackagePurposeLibrary
		license = m.spdxLicense(c)

		if c.SrcName != "" {
			sourceInfo = fmt.Sprintf("%s: %s %s", SourcePackagePrefix, c.SrcName, c.SrcVersion)
		} else if c.SrcFile != "" {
			sourceInfo = fmt.Sprintf("%s: %s", SourceFilePrefix, c.SrcFile)
		}

		supplier = &spdx.Supplier{Supplier: PackageSupplierNoAssertion}
		if c.Supplier != "" {
			supplier = &spdx.Supplier{
				SupplierType: PackageSupplierOrganization, // Always use "Organization" at the moment as it is difficult to distinguish between "Person" or "Organization".
				Supplier:     c.Supplier,
			}
		}
	}

	var pkgExtRefs []*spdx.PackageExternalReference
	if c.PkgIdentifier.PURL != nil {
		pkgExtRefs = []*spdx.PackageExternalReference{m.purlExternalReference(c.PkgIdentifier.PURL.String())}
	}

	var digests []digest.Digest
	for _, f := range c.Files {
		// The file digests are stored separately.
		if f.Path != "" {
			continue
		}
		digests = append(digests, f.Digests...)
	}

	return spdx.Package{
		PackageSPDXIdentifier:     elementID(elementType, pkgID),
		PackageName:               spdxPkgName(c),
		PackageVersion:            c.Version,
		PrimaryPackagePurpose:     purpose,
		PackageDownloadLocation:   pkgDownloadLocation,
		PackageExternalReferences: pkgExtRefs,
		Annotations:               m.spdxAnnotations(c, timeNow),
		PackageSourceInfo:         sourceInfo,
		PackageSupplier:           supplier,
		PackageChecksums:          m.spdxChecksums(digests),

		// The Declared License is what the authors of a project believe govern the package
		PackageLicenseConcluded: license,

		// The Concluded License field is the license the SPDX file creator believes governs the package
		PackageLicenseDeclared: license,
	}, nil
}

func spdxPkgName(component *core.Component) string {
	if p := component.PkgIdentifier.PURL; p != nil && component.Group != "" {
		if p.Type == packageurl.TypeMaven || p.Type == packageurl.TypeGradle {
			return component.Group + ":" + component.Name
		}
		return component.Group + "/" + component.Name
	}
	return component.Name
}
func (m *Marshaler) spdxAnnotations(c *core.Component, timeNow string) []spdx.Annotation {
	var annotations []spdx.Annotation
	for _, p := range c.Properties {
		// Add properties that are not in other fields.
		if !slices.Contains(duplicateProperties, p.Name) {
			annotations = m.appendAnnotation(annotations, timeNow, p.Name, p.Value)
		}
	}
	return annotations
}

func (m *Marshaler) spdxLicense(c *core.Component) string {
	if len(c.Licenses) == 0 {
		return noAssertionField
	}
	return NormalizeLicense(c.Licenses)
}

func (m *Marshaler) spdxChecksums(digests []digest.Digest) []common.Checksum {
	var checksums []common.Checksum
	for _, d := range digests {
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
		checksums = append(checksums, spdx.Checksum{
			Algorithm: alg,
			Value:     d.Encoded(),
		})
	}

	return checksums
}

func (m *Marshaler) spdxFiles(c *core.Component) ([]*spdx.File, error) {
	var files []*spdx.File
	for _, file := range c.Files {
		if file.Path == "" || len(file.Digests) == 0 {
			continue
		}
		spdxFile, err := m.spdxFile(file.Path, file.Digests)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse file: %w", err)
		}
		files = append(files, spdxFile)
	}
	return files, nil
}

func (m *Marshaler) spdxFile(filePath string, digests []digest.Digest) (*spdx.File, error) {
	pkgID, err := calcPkgID(m.hasher, filePath)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s package ID: %w", filePath, err)
	}
	return &spdx.File{
		FileSPDXIdentifier: spdx.ElementID(fmt.Sprintf("File-%s", pkgID)),
		FileName:           filePath,
		Checksums:          m.spdxChecksums(digests),
	}, nil
}

func (m *Marshaler) spdxRelationShip(refA, refB spdx.ElementID, operator string) *spdx.Relationship {
	ref := spdx.Relationship{
		RefA:         common.MakeDocElementID("", string(refA)),
		RefB:         common.MakeDocElementID("", string(refB)),
		Relationship: operator,
	}
	return &ref
}

func (m *Marshaler) spdxRelationshipType(relType core.RelationshipType) string {
	switch relType {
	case core.RelationshipDependsOn:
		return RelationShipDependsOn
	case core.RelationshipContains:
		return RelationShipContains
	case core.RelationshipDescribes:
		return RelationShipDescribe
	default:
		return RelationShipDependsOn
	}
}

func sortPackages(pkgs []*spdx.Package) {
	sort.Slice(pkgs, func(i, j int) bool {
		switch {
		case pkgs[i].PrimaryPackagePurpose != pkgs[j].PrimaryPackagePurpose:
			return pkgs[i].PrimaryPackagePurpose < pkgs[j].PrimaryPackagePurpose
		case pkgs[i].PackageName != pkgs[j].PackageName:
			return pkgs[i].PackageName < pkgs[j].PackageName
		default:
			return pkgs[i].PackageSPDXIdentifier < pkgs[j].PackageSPDXIdentifier
		}
	})
}

func sortRelationships(rels []*spdx.Relationship) {
	sort.Slice(rels, func(i, j int) bool {
		switch {
		case rels[i].RefA.ElementRefID != rels[j].RefA.ElementRefID:
			return rels[i].RefA.ElementRefID < rels[j].RefA.ElementRefID
		case rels[i].RefB.ElementRefID != rels[j].RefB.ElementRefID:
			return rels[i].RefB.ElementRefID < rels[j].RefB.ElementRefID
		default:
			return rels[i].Relationship < rels[j].Relationship
		}
	})
}

func sortFiles(files []*spdx.File) {
	sort.Slice(files, func(i, j int) bool {
		switch {
		case files[i].FileName != files[j].FileName:
			return files[i].FileName < files[j].FileName
		default:
			return files[i].FileSPDXIdentifier < files[j].FileSPDXIdentifier
		}
	})
}

func elementID(elementType, pkgID string) spdx.ElementID {
	return spdx.ElementID(fmt.Sprintf("%s-%s", elementType, pkgID))
}

func getDocumentNamespace(root *core.Component) string {
	return fmt.Sprintf("%s/%s/%s-%s",
		DocumentNamespace,
		string(root.Type),
		strings.ReplaceAll(strings.ReplaceAll(root.Name, "https://", ""), "http://", ""), // remove http(s):// prefix when scanning repos
		uuid.New().String(),
	)
}

func calcPkgID(h Hash, v any) (string, error) {
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

func NormalizeLicense(licenses []string) string {
	license := strings.Join(lo.Map(licenses, func(license string, index int) string {
		// e.g. GPL-3.0-with-autoconf-exception
		license = strings.ReplaceAll(license, "-with-", " WITH ")
		license = strings.ReplaceAll(license, "-WITH-", " WITH ")

		return fmt.Sprintf("(%s)", license)
	}), " AND ")
	s, err := expression.Normalize(license, licensing.NormalizeLicense, expression.NormalizeForSPDX)
	if err != nil {
		// Not fail on the invalid license
		log.Warn("Unable to marshal SPDX licenses", log.String("license", license))
		return ""
	}
	return s
}

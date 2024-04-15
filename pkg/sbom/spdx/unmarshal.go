package spdx

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/tagvalue"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/sbom/core"
)

type SPDX struct {
	*core.BOM

	trivySBOM    bool
	pkgFilePaths map[common.ElementID]string
}

func NewTVDecoder(r io.Reader) *TVDecoder {
	return &TVDecoder{r: r}
}

type TVDecoder struct {
	r io.Reader
}

func (tv *TVDecoder) Decode(v interface{}) error {
	spdxDocument, err := tagvalue.Read(tv.r)
	if err != nil {
		return xerrors.Errorf("failed to load tag-value spdx: %w", err)
	}

	a, ok := v.(*SPDX)
	if !ok {
		return xerrors.Errorf("invalid struct type tag-value decoder needed SPDX struct")
	}
	if err = a.unmarshal(spdxDocument); err != nil {
		return xerrors.Errorf("failed to unmarshal spdx: %w", err)
	}

	return nil
}

func (s *SPDX) UnmarshalJSON(b []byte) error {
	if s.BOM == nil {
		s.BOM = core.NewBOM(core.Options{})
	}
	if s.pkgFilePaths == nil {
		s.pkgFilePaths = make(map[common.ElementID]string)
	}

	spdxDocument, err := json.Read(bytes.NewReader(b))
	if err != nil {
		return xerrors.Errorf("failed to load spdx json: %w", err)
	}

	if err = s.unmarshal(spdxDocument); err != nil {
		return xerrors.Errorf("failed to unmarshal spdx: %w", err)
	}
	return nil
}

func (s *SPDX) unmarshal(spdxDocument *spdx.Document) error {
	s.trivySBOM = s.isTrivySBOM(spdxDocument)

	// Parse files and find file paths for packages
	s.parseFiles(spdxDocument)

	// Convert all SPDX packages into Trivy components
	components, err := s.parsePackages(spdxDocument)
	if err != nil {
		return xerrors.Errorf("package parse error: %w", err)
	}

	// Parse relationships and build the dependency graph
	for _, rel := range spdxDocument.Relationships {
		// Skip the DESCRIBES relationship.
		if rel.Relationship == common.TypeRelationshipDescribe || rel.Relationship == "DESCRIBE" {
			continue
		}

		compA, ok := components[rel.RefA.ElementRefID]
		if !ok { // Skip if parent is not Package
			continue
		}

		compB, ok := components[rel.RefB.ElementRefID]
		if !ok { // Skip if child is not Package
			continue
		}

		s.BOM.AddRelationship(compA, compB, s.parseRelationshipType(rel.Relationship))
	}

	return nil
}

// parseFiles parses Relationships and finds filepaths for packages
func (s *SPDX) parseFiles(spdxDocument *spdx.Document) {
	fileSPDXIdentifierMap := lo.SliceToMap(spdxDocument.Files, func(file *spdx.File) (common.ElementID, *spdx.File) {
		return file.FileSPDXIdentifier, file
	})

	for _, rel := range spdxDocument.Relationships {
		if rel.Relationship != common.TypeRelationshipContains && rel.Relationship != "CONTAIN" {
			// Skip the DESCRIBES relationship.
			continue
		}

		// hasFiles field is deprecated
		// https://github.com/spdx/tools-golang/issues/171
		// hasFiles values converted in Relationships
		// https://github.com/spdx/tools-golang/pull/201
		if isFile(rel.RefB.ElementRefID) {
			file, ok := fileSPDXIdentifierMap[rel.RefB.ElementRefID]
			if ok {
				// Save filePaths for packages
				// Insert filepath will be later
				s.pkgFilePaths[rel.RefA.ElementRefID] = file.FileName
			}
			continue
		}
	}
}

func (s *SPDX) parsePackages(spdxDocument *spdx.Document) (map[common.ElementID]*core.Component, error) {
	// Find a root package
	var rootID common.ElementID
	for _, rel := range spdxDocument.Relationships {
		if rel.RefA.ElementRefID == DocumentSPDXIdentifier && rel.Relationship == RelationShipDescribe {
			rootID = rel.RefB.ElementRefID
			break
		}
	}

	// Convert packages into components
	components := make(map[common.ElementID]*core.Component)
	for _, pkg := range spdxDocument.Packages {
		component, err := s.parsePackage(*pkg)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse package: %w", err)
		}
		components[pkg.PackageSPDXIdentifier] = component

		if pkg.PackageSPDXIdentifier == rootID {
			component.Root = true
		}
		s.BOM.AddComponent(component)
	}
	return components, nil
}

func (s *SPDX) parsePackage(spdxPkg spdx.Package) (*core.Component, error) {
	var err error
	component := &core.Component{
		Type:    s.parseType(spdxPkg),
		Name:    spdxPkg.PackageName,
		Version: spdxPkg.PackageVersion,
	}

	// PURL
	if component.PkgID.PURL, err = s.parseExternalReferences(spdxPkg.PackageExternalReferences); err != nil {
		return nil, xerrors.Errorf("external references error: %w", err)
	}

	// License
	if spdxPkg.PackageLicenseDeclared != "NONE" {
		component.Licenses = strings.Split(spdxPkg.PackageLicenseDeclared, ",")
	}

	// Source package
	if strings.HasPrefix(spdxPkg.PackageSourceInfo, SourcePackagePrefix) {
		srcPkgName := strings.TrimPrefix(spdxPkg.PackageSourceInfo, fmt.Sprintf("%s: ", SourcePackagePrefix))
		component.SrcName, component.SrcVersion, _ = strings.Cut(srcPkgName, " ")
	}

	// Files
	// TODO: handle checksums as well
	if path, ok := s.pkgFilePaths[spdxPkg.PackageSPDXIdentifier]; ok {
		component.Files = []core.File{
			{Path: path},
		}
	} else if len(spdxPkg.Files) > 0 {
		component.Files = []core.File{
			{Path: spdxPkg.Files[0].FileName}, // Take the first file name
		}
	}

	// Attributions
	for _, attr := range spdxPkg.PackageAttributionTexts {
		k, v, ok := strings.Cut(attr, ": ")
		if !ok {
			continue
		}
		component.Properties = append(component.Properties, core.Property{
			Name:  k,
			Value: v,
		})
	}

	// For backward-compatibility
	// Older Trivy versions put the file path in "sourceInfo" and the package type in "name".
	if s.trivySBOM && component.Type == core.TypeApplication && spdxPkg.PackageSourceInfo != "" {
		component.Name = spdxPkg.PackageSourceInfo
		component.Properties = append(component.Properties, core.Property{
			Name:  core.PropertyType,
			Value: spdxPkg.PackageName,
		})
	}

	return component, nil
}

func (s *SPDX) parseType(pkg spdx.Package) core.ComponentType {
	id := string(pkg.PackageSPDXIdentifier)
	switch {
	case strings.HasPrefix(id, ElementOperatingSystem):
		return core.TypeOS
	case strings.HasPrefix(id, ElementApplication):
		return core.TypeApplication
	case strings.HasPrefix(id, ElementPackage):
		return core.TypeLibrary
	default:
		return core.TypeLibrary // unknown is handled as a library
	}
}

func (s *SPDX) parseRelationshipType(rel string) core.RelationshipType {
	switch rel {
	case common.TypeRelationshipDescribe:
		return core.RelationshipDescribes
	case common.TypeRelationshipContains, "CONTAIN":
		return core.RelationshipContains
	case common.TypeRelationshipDependsOn:
		return core.RelationshipDependsOn
	default:
		return core.RelationshipContains
	}
}

func (s *SPDX) parseExternalReferences(refs []*spdx.PackageExternalReference) (*packageurl.PackageURL, error) {
	for _, ref := range refs {
		// Extract the package information from PURL
		if ref.RefType != RefTypePurl || ref.Category != CategoryPackageManager {
			continue
		}

		packageURL, err := packageurl.FromString(ref.Locator)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse purl from string: %w", err)
		}
		return &packageURL, nil
	}
	return nil, nil
}

func (s *SPDX) isTrivySBOM(spdxDocument *spdx.Document) bool {
	if spdxDocument == nil || spdxDocument.CreationInfo == nil || spdxDocument.CreationInfo.Creators == nil {
		return false
	}

	for _, c := range spdxDocument.CreationInfo.Creators {
		if c.CreatorType == "Tool" && strings.HasPrefix(c.Creator, "trivy") {
			return true
		}
	}
	return false
}

func isFile(elementID spdx.ElementID) bool {
	return strings.HasPrefix(string(elementID), ElementFile)
}

package spdx

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/tagvalue"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	errUnknownPackageFormat = xerrors.New("unknown package format")
)

type SPDX struct {
	*types.SBOM
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
	err = a.unmarshal(spdxDocument)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal spdx: %w", err)
	}

	return nil
}

func (s *SPDX) UnmarshalJSON(b []byte) error {
	spdxDocument, err := json.Read(bytes.NewReader(b))
	if err != nil {
		return xerrors.Errorf("failed to load spdx json: %w", err)
	}
	err = s.unmarshal(spdxDocument)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal spdx: %w", err)
	}
	return nil
}

func (s *SPDX) unmarshal(spdxDocument *spdx.Document) error {
	var osPkgs []ftypes.Package
	apps := map[common.ElementID]*ftypes.Application{}
	packageSPDXIdentifierMap := createPackageSPDXIdentifierMap(spdxDocument.Packages)
	packageFilePaths := getPackageFilePaths(spdxDocument)

	relationships := lo.Filter(spdxDocument.Relationships, func(rel *spdx.Relationship, _ int) bool {
		// Skip the DESCRIBES relationship.
		return rel.Relationship != common.TypeRelationshipDescribe && rel.Relationship != "DESCRIBE"
	})

	// Package relationships would be as belows:
	// - Root (container image, filesystem, etc.)
	//   - Operating System (debian 10)
	//     - OS package A
	//     - OS package B
	//   - Application 1 (package-lock.json)
	//     - Node.js package A
	//     - Node.js package B
	//   - Application 2 (Pipfile.lock)
	//     - Python package A
	//     - Python package B
	for _, rel := range relationships {
		pkgA := packageSPDXIdentifierMap[string(rel.RefA.ElementRefID)]
		pkgB := packageSPDXIdentifierMap[string(rel.RefB.ElementRefID)]

		if pkgA == nil || pkgB == nil {
			// Skip the missing pkg relationship.
			continue
		}

		switch {
		// Relationship: root package => OS
		case isOperatingSystem(pkgB.PackageSPDXIdentifier):
			s.SBOM.OS = parseOS(*pkgB)
		// Relationship: OS => OS package
		case isOperatingSystem(pkgA.PackageSPDXIdentifier):
			pkg, _, err := parsePkg(*pkgB, packageFilePaths)
			if errors.Is(err, errUnknownPackageFormat) {
				continue
			} else if err != nil {
				return xerrors.Errorf("failed to parse os package: %w", err)
			}
			osPkgs = append(osPkgs, *pkg)
		// Relationship: root package => application
		case isApplication(pkgB.PackageSPDXIdentifier):
			// pass
		// Relationship: application => language-specific package
		case isApplication(pkgA.PackageSPDXIdentifier):
			app, ok := apps[pkgA.PackageSPDXIdentifier]
			if !ok {
				app = initApplication(*pkgA)
				apps[pkgA.PackageSPDXIdentifier] = app
			}

			lib, _, err := parsePkg(*pkgB, packageFilePaths)
			if errors.Is(err, errUnknownPackageFormat) {
				continue
			} else if err != nil {
				return xerrors.Errorf("failed to parse language-specific package: %w", err)
			}
			app.Libraries = append(app.Libraries, *lib)
		}
	}

	// Fill OS packages
	if len(osPkgs) > 0 {
		s.Packages = []ftypes.PackageInfo{{Packages: osPkgs}}
	}

	// Fill applications
	for _, app := range apps {
		s.SBOM.Applications = append(s.SBOM.Applications, *app)
	}

	// Fallback for when there are no effective relationships.
	if len(relationships) == 0 {
		if err := s.parsePackages(spdxDocument); err != nil {
			return err
		}
	}

	// Keep the original document
	s.SPDX = spdxDocument
	return nil
}

// parsePackages processes the packages and categorizes them into OS packages and application packages.
// Note that all language-specific packages are treated as a single application.
func (s *SPDX) parsePackages(spdxDocument *spdx.Document) error {
	var (
		osPkgs []ftypes.Package
		app    ftypes.Application
	)

	for _, p := range spdxDocument.Packages {
		pkg, pkgType, err := parsePkg(*p, nil)
		if errors.Is(err, errUnknownPackageFormat) {
			continue
		} else if err != nil {
			return xerrors.Errorf("failed to parse package: %w", err)
		}
		switch pkgType {
		case purl.TypeAPK, packageurl.TypeDebian, packageurl.TypeRPM:
			osPkgs = append(osPkgs, *pkg)
		default:
			// Language-specific packages
			if app.Type == "" {
				app.Type = pkgType
			}
			app.Libraries = append(app.Libraries, *pkg)
		}
	}
	if len(osPkgs) > 0 {
		s.Packages = []ftypes.PackageInfo{{Packages: osPkgs}}
	}
	if len(app.Libraries) > 0 {
		s.SBOM.Applications = append(s.SBOM.Applications, app)
	}
	return nil
}

func createPackageSPDXIdentifierMap(packages []*spdx.Package) map[string]*spdx.Package {
	ret := make(map[string]*spdx.Package)
	for _, info := range packages {
		ret[string(info.PackageSPDXIdentifier)] = info
	}
	return ret
}

func createFileSPDXIdentifierMap(files []*spdx.File) map[string]*spdx.File {
	ret := make(map[string]*spdx.File)
	for _, file := range files {
		ret[string(file.FileSPDXIdentifier)] = file
	}
	return ret
}

func isOperatingSystem(elementID spdx.ElementID) bool {
	return strings.HasPrefix(string(elementID), ElementOperatingSystem)
}

func isApplication(elementID spdx.ElementID) bool {
	return strings.HasPrefix(string(elementID), ElementApplication)
}

func isFile(elementID spdx.ElementID) bool {
	return strings.HasPrefix(string(elementID), ElementFile)
}

func initApplication(pkg spdx.Package) *ftypes.Application {
	app := &ftypes.Application{
		Type:     pkg.PackageName,
		FilePath: pkg.PackageSourceInfo,
	}
	if pkg.PackageName == ftypes.NodePkg || pkg.PackageName == ftypes.PythonPkg ||
		pkg.PackageName == ftypes.GemSpec || pkg.PackageName == ftypes.Jar || pkg.PackageName == ftypes.CondaPkg {
		app.FilePath = ""
	}
	return app
}

func parseOS(pkg spdx.Package) ftypes.OS {
	return ftypes.OS{
		Family: pkg.PackageName,
		Name:   pkg.PackageVersion,
	}
}

func parsePkg(spdxPkg spdx.Package, packageFilePaths map[string]string) (*ftypes.Package, string, error) {
	pkg, pkgType, err := parseExternalReferences(spdxPkg.PackageExternalReferences)
	if err != nil {
		return nil, "", xerrors.Errorf("external references error: %w", err)
	}

	if spdxPkg.PackageLicenseDeclared != "NONE" {
		pkg.Licenses = strings.Split(spdxPkg.PackageLicenseDeclared, ",")
	}

	if strings.HasPrefix(spdxPkg.PackageSourceInfo, SourcePackagePrefix) {
		srcPkgName := strings.TrimPrefix(spdxPkg.PackageSourceInfo, fmt.Sprintf("%s: ", SourcePackagePrefix))
		pkg.SrcEpoch, pkg.SrcName, pkg.SrcVersion, pkg.SrcRelease, err = parseSourceInfo(pkgType, srcPkgName)
		if err != nil {
			return nil, "", xerrors.Errorf("failed to parse source info: %w", err)
		}
	}

	if path, ok := packageFilePaths[string(spdxPkg.PackageSPDXIdentifier)]; ok {
		pkg.FilePath = path
	} else if len(spdxPkg.Files) > 0 {
		// Take the first file name
		pkg.FilePath = spdxPkg.Files[0].FileName
	}

	pkg.ID = lookupAttributionTexts(spdxPkg.PackageAttributionTexts, PropertyPkgID)
	pkg.Layer.Digest = lookupAttributionTexts(spdxPkg.PackageAttributionTexts, PropertyLayerDigest)
	pkg.Layer.DiffID = lookupAttributionTexts(spdxPkg.PackageAttributionTexts, PropertyLayerDiffID)

	return pkg, pkgType, nil
}

func parseExternalReferences(refs []*spdx.PackageExternalReference) (*ftypes.Package, string, error) {
	for _, ref := range refs {
		// Extract the package information from PURL
		if ref.RefType == RefTypePurl && ref.Category == CategoryPackageManager {
			packageURL, err := purl.FromString(ref.Locator)
			if err != nil {
				return nil, "", xerrors.Errorf("failed to parse purl from string: %w", err)
			}
			pkg := packageURL.Package()
			pkg.Ref = ref.Locator
			return pkg, packageURL.PackageType(), nil
		}
	}
	return nil, "", errUnknownPackageFormat
}

func lookupAttributionTexts(attributionTexts []string, key string) string {
	for _, text := range attributionTexts {
		if strings.HasPrefix(text, key) {
			return strings.TrimPrefix(text, fmt.Sprintf("%s: ", key))
		}
	}
	return ""
}

func parseSourceInfo(pkgType, sourceInfo string) (epoch int, name, ver, rel string, err error) {
	srcNameVersion := strings.TrimPrefix(sourceInfo, fmt.Sprintf("%s: ", SourcePackagePrefix))
	ss := strings.Split(srcNameVersion, " ")
	if len(ss) != 2 {
		return 0, "", "", "", xerrors.Errorf("invalid source info (%s)", sourceInfo)
	}
	name = ss[0]
	if pkgType == packageurl.TypeRPM {
		v := version.NewVersion(ss[1])
		epoch = v.Epoch()
		ver = v.Version()
		rel = v.Release()
	} else {
		ver = ss[1]
	}
	return epoch, name, ver, rel, nil
}

// getPackageFilePaths parses Relationships and finds filepaths for packages
func getPackageFilePaths(spdxDocument *spdx.Document) map[string]string {
	packageFilePaths := map[string]string{}
	fileSPDXIdentifierMap := createFileSPDXIdentifierMap(spdxDocument.Files)
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
			file, ok := fileSPDXIdentifierMap[string(rel.RefB.ElementRefID)]
			if ok {
				// Save filePaths for packages
				// Insert filepath will be later
				packageFilePaths[string(rel.RefA.ElementRefID)] = file.FileName
			}
			continue
		}
	}
	return packageFilePaths
}

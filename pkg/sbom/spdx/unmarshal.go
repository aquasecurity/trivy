package spdx

import (
	"bytes"
	"fmt"
	"io"
	"strings"

	version "github.com/knqyf263/go-rpm-version"
	"github.com/package-url/packageurl-go"
	"github.com/spdx/tools-golang/jsonloader"
	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/tvloader"
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/sbom"
)

var (
	errInvalidPackageFormat = xerrors.New("invalid package format")
)

type SPDX struct {
	*sbom.SBOM

	relationships map[spdx.ElementID][]spdx.ElementID
	packages      map[spdx.ElementID]*spdx.Package2_2
}

func NewTVDecoder(r io.Reader) *TVDecoder {
	return &TVDecoder{r: r}
}

type TVDecoder struct {
	r io.Reader
}

func (tv *TVDecoder) Decode(v interface{}) error {
	spdxDocument, err := tvloader.Load2_2(tv.r)
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
	spdxDocument, err := jsonloader.Load2_2(bytes.NewReader(b))
	if err != nil {
		return xerrors.Errorf("failed to load spdx json: %w", err)
	}
	err = s.unmarshal(spdxDocument)
	if err != nil {
		return xerrors.Errorf("failed to unmarshal spdx: %w", err)
	}
	return nil
}

func (s *SPDX) unmarshal(spdxDocument *spdx.Document2_2) error {
	s.relationships = relationshipMap(spdxDocument.Relationships)
	s.packages = spdxDocument.Packages

	for pkgID := range s.relationships {
		pkg := s.packages[pkgID]
		switch {
		case strings.HasPrefix(string(pkg.PackageSPDXIdentifier), ElementOperatingSystem):
			s.SBOM.OS = parseOS(pkg)
			pkgs, err := s.parsePkgs(pkg.PackageSPDXIdentifier)
			if err != nil {
				return xerrors.Errorf("failed to parse os packages: %w", err)
			}
			if len(pkgs) != 0 {
				s.SBOM.Packages = []ftypes.PackageInfo{{Packages: pkgs}}
			}

		case strings.HasPrefix(string(pkg.PackageSPDXIdentifier), ElementApplication):
			app, err := s.parseApplication(pkg)
			if err != nil {
				return xerrors.Errorf("failed to parse application: %w", err)
			}
			s.SBOM.Applications = append(s.SBOM.Applications, *app)
		}
	}

	return nil
}

func (s *SPDX) parseApplication(pkg *spdx.Package2_2) (*ftypes.Application, error) {
	pkgs, err := s.parsePkgs(pkg.PackageSPDXIdentifier)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse language packages: %w", err)
	}
	app := &ftypes.Application{
		Type:      pkg.PackageName,
		FilePath:  pkg.PackageSourceInfo,
		Libraries: pkgs,
	}
	if pkg.PackageName == ftypes.NodePkg || pkg.PackageName == ftypes.PythonPkg ||
		pkg.PackageName == ftypes.GemSpec || pkg.PackageName == ftypes.Jar {
		app.FilePath = ""
	}
	return app, nil

}

func (s *SPDX) parsePkgs(id spdx.ElementID) ([]ftypes.Package, error) {
	pkgIDs := s.relationships[id]

	var pkgs []ftypes.Package
	for _, id := range pkgIDs {
		spdxPkg := s.packages[id]
		pkg, err := parsePkg(spdxPkg)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse package: %w", err)
		}

		pkgs = append(pkgs, *pkg)
	}
	return pkgs, nil
}

func parseOS(pkg *spdx.Package2_2) *ftypes.OS {
	return &ftypes.OS{
		Family: pkg.PackageName,
		Name:   pkg.PackageVersion,
	}
}

func parsePkg(package2_2 *spdx.Package2_2) (*ftypes.Package, error) {
	var (
		pkg *ftypes.Package
		typ string
	)
	for _, ref := range package2_2.PackageExternalReferences {
		if ref.RefType == RefTypePurl && ref.Category == CategoryPackageManager {
			packageURL, err := purl.FromString(ref.Locator)
			if err != nil {
				return nil, xerrors.Errorf("failed to parse purl from string: %w", err)
			}
			pkg = packageURL.Package()
			pkg.Ref = ref.Locator
			typ = packageURL.Type
			break
		}
	}
	if pkg == nil {
		return nil, errInvalidPackageFormat
	}

	if package2_2.PackageLicenseDeclared != "NONE" {
		pkg.Licenses = strings.Split(package2_2.PackageLicenseDeclared, ",")
	}
	pkg.Name = package2_2.PackageName
	pkg.Version = package2_2.PackageVersion

	if strings.HasPrefix(package2_2.PackageSourceInfo, SourcePackagePrefix) {
		var err error
		srcPkgName := strings.TrimPrefix(package2_2.PackageSourceInfo, fmt.Sprintf("%s: ", SourcePackagePrefix))
		pkg.SrcEpoch, pkg.SrcName, pkg.SrcVersion, pkg.SrcRelease, err = parseSourceInfo(typ, srcPkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse source info: %w", err)
		}
	}
	for _, f := range package2_2.Files {
		pkg.FilePath = f.FileName
	}

	pkg.Layer.Digest = lookupAttributionTexts(package2_2.PackageAttributionTexts, PropertyLayerDigest)
	pkg.Layer.DiffID = lookupAttributionTexts(package2_2.PackageAttributionTexts, PropertyLayerDiffID)

	return pkg, nil
}

func lookupAttributionTexts(attributionTexts []string, key string) (value string) {
	for _, text := range attributionTexts {
		if strings.HasPrefix(text, key) {
			return strings.TrimPrefix(text, fmt.Sprintf("%s: ", key))
		}
	}

	return ""
}

func parseSourceInfo(typ, sourceInfo string) (epoch int, name, ver, rel string, err error) {
	srcNameVersion := strings.TrimPrefix(sourceInfo, fmt.Sprintf("%s: ", SourcePackagePrefix))
	ss := strings.Split(srcNameVersion, " ")
	if len(ss) != 2 {
		return 0, "", "", "", xerrors.Errorf("invalid source info (%s)", sourceInfo)
	}
	name = ss[0]
	if typ == packageurl.TypeRPM {
		v := version.NewVersion(ss[1])
		epoch = v.Epoch()
		ver = v.Version()
		rel = v.Release()
	} else {
		ver = ss[1]
	}
	return epoch, name, ver, rel, nil
}

func relationshipMap(relationships []*spdx.Relationship2_2) map[spdx.ElementID][]spdx.ElementID {
	relationshipMap := make(map[spdx.ElementID][]spdx.ElementID)
	var rootElement spdx.ElementID
	for _, relationship := range relationships {
		if relationship.Relationship == RelationShipDescribe {
			rootElement = relationship.RefB.ElementRefID
		}
	}
	for _, relationship := range relationships {
		if relationship.Relationship == RelationShipContains {
			if relationship.RefA.ElementRefID == rootElement {
				relationshipMap[relationship.RefB.ElementRefID] = []spdx.ElementID{}
			}
		}
	}
	for _, relationship := range relationships {
		if relationship.Relationship == RelationShipDependsOn {
			if array, ok := relationshipMap[relationship.RefA.ElementRefID]; ok {
				relationshipMap[relationship.RefA.ElementRefID] = append(array, relationship.RefB.ElementRefID)
			}
		}
	}

	return relationshipMap
}

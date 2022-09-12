package spdx

import (
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
	errUnexpectedSourceNameFormat = xerrors.New("unexpected source name format")
	errInvalidPackageFormat       = xerrors.New("invalid package format")
)

type Unmarshaler struct {
	relationships map[spdx.ElementID][]spdx.ElementID
	packages      map[spdx.ElementID]*spdx.Package2_2
	format        string
}

const (
	FormatTV   = "tv"
	FormatJSON = "json"
)

func NewUnmarshaler() sbom.Unmarshaler {
	return &Unmarshaler{format: FormatTV}
}
func NewJSONUnmarshaler() sbom.Unmarshaler {
	return &Unmarshaler{format: FormatJSON}
}

func (u *Unmarshaler) parseDocument(r io.Reader) (*spdx.Document2_2, error) {
	switch u.format {
	case FormatTV:
		spdxDocument, err := tvloader.Load2_2(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to load spdx tag-value: %w", err)
		}
		return spdxDocument, nil
	case FormatJSON:
		spdxDocument, err := jsonloader.Load2_2(r)
		if err != nil {
			return nil, xerrors.Errorf("failed to load spdx json: %w", err)
		}
		return spdxDocument, nil
	default:
		return nil, xerrors.New("invalid spdx format")
	}
}

func (u *Unmarshaler) Unmarshal(r io.Reader) (sbom.SBOM, error) {
	spdxDocument, err := u.parseDocument(r)
	if err != nil {
		return sbom.SBOM{}, xerrors.Errorf("failed to parse spdx document: %w", err)
	}

	u.relationships = relationshipMap(spdxDocument.Relationships)
	u.packages = spdxDocument.Packages
	var (
		osInfo   *ftypes.OS
		apps     []ftypes.Application
		pkgInfos []ftypes.PackageInfo
	)

	for pkgID := range u.relationships {
		pkg := u.packages[pkgID]
		switch {
		case strings.HasPrefix(string(pkg.PackageSPDXIdentifier), ElementOperatingSystem):
			osInfo = parseOS(pkg)
			pkgs, err := u.parsePkgs(pkg.PackageSPDXIdentifier)
			if err != nil {
				return sbom.SBOM{}, xerrors.Errorf("failed to parse os packages: %w", err)
			}
			if len(pkgs) != 0 {
				pkgInfos = []ftypes.PackageInfo{{Packages: pkgs}}
			}

		case strings.HasPrefix(string(pkg.PackageSPDXIdentifier), ElementApplication):
			app, err := u.parseApplication(pkg)
			if err != nil {
				return sbom.SBOM{}, xerrors.Errorf("failed to parse application: %w", err)
			}
			apps = append(apps, *app)
		}
	}

	return sbom.SBOM{
		OS:           osInfo,
		Applications: apps,
		Packages:     pkgInfos,
	}, nil
}

func (u *Unmarshaler) parseApplication(pkg *spdx.Package2_2) (*ftypes.Application, error) {
	pkgs, err := u.parsePkgs(pkg.PackageSPDXIdentifier)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse language packages: %w", err)
	}
	app := &ftypes.Application{
		Type:      pkg.PackageVersion,
		FilePath:  pkg.PackageName,
		Libraries: pkgs,
	}
	if pkg.PackageVersion == ftypes.NodePkg || pkg.PackageVersion == ftypes.PythonPkg ||
		pkg.PackageVersion == ftypes.GemSpec || pkg.PackageVersion == ftypes.Jar {
		app.FilePath = ""
	}
	return app, nil

}

func (u *Unmarshaler) parsePkgs(id spdx.ElementID) ([]ftypes.Package, error) {
	pkgIDs := u.relationships[id]

	var pkgs []ftypes.Package
	for _, id := range pkgIDs {
		spdxPkg := u.packages[id]
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

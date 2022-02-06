package purl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"

	"github.com/package-url/packageurl-go"
)

func NewPackageURL(t string, fos *types.OS, pkg types.Package) packageurl.PackageURL {
	ptype := purlType(t)

	var qualifiers packageurl.Qualifiers
	if fos != nil {
		qualifiers = parseQualifier(pkg, fos.Name)
	}

	name := pkg.Name
	version := utils.FormatVersion(pkg)
	namespace := ""

	switch ptype {
	case packageurl.TypeRPM:
		ns, qs := parseRPM(fos, pkg.Modularitylabel)
		namespace = ns
		qualifiers = append(qualifiers, qs...)
	case packageurl.TypeDebian:
		qualifiers = append(qualifiers, parseDeb(fos)...)
		namespace = fos.Family
	case string(analyzer.TypeApk): // TODO: replace with packageurl.TypeApk
		qualifiers = append(qualifiers, parseApk(fos)...)
		namespace = fos.Family
	case packageurl.TypeMaven:
		namespace, name = parseMaven(name)
	case packageurl.TypePyPi:
		name = parsePyPI(name)
	case packageurl.TypeComposer:
		namespace, name = parseComposer(name)
	case packageurl.TypeGolang:
		namespace, name = parseGolang(name)
	case packageurl.TypeNPM:
		namespace, name = parseNpm(name)
	}
	return *packageurl.NewPackageURL(ptype, namespace, name, version, qualifiers, "")
}

func parseApk(fos *types.OS) packageurl.Qualifiers {
	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fos.Name,
		},
	}
}

func parseDeb(fos *types.OS) packageurl.Qualifiers {
	distro := fmt.Sprintf("%s-%s", fos.Family, fos.Name)
	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: distro,
		},
	}
}

func parseRPM(fos *types.OS, modularityLabel string) (string, packageurl.Qualifiers) {
	// SLES string has whitespace
	family := fos.Family
	if fos.Family == os.SLES {
		family = "sles"
	}

	distro := fmt.Sprintf("%s-%s", family, fos.Name)

	qualifiers := packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: distro,
		},
	}

	if modularityLabel != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "modularitylabel",
			Value: modularityLabel,
		})
	}
	return family, qualifiers
}

func parseMaven(pkgName string) (string, string) {
	var namespace string
	name := strings.ReplaceAll(pkgName, ":", "/")
	index := strings.LastIndex(name, "/")
	if index != -1 {
		namespace = name[:index]
		name = name[index+1:]
	}
	return namespace, name
}

func parseGolang(pkgName string) (string, string) {
	var namespace string

	name := strings.ToLower(pkgName)
	index := strings.LastIndex(name, "/")
	if index != -1 {
		namespace = name[:index]
		name = name[index+1:]
	}
	return namespace, name
}

func parsePyPI(pkgName string) string {
	return strings.ToLower(strings.ReplaceAll(pkgName, "_", "-"))
}

func parseComposer(pkgName string) (string, string) {
	var namespace, name string

	index := strings.LastIndex(pkgName, "/")
	if index != -1 {
		namespace = pkgName[:index]
		name = pkgName[index+1:]
	}
	return namespace, name
}

func parseNpm(pkgName string) (string, string) {
	var namespace string

	name := strings.ToLower(pkgName)
	index := strings.LastIndex(pkgName, "/")
	if index != -1 {
		namespace = name[:index]
		name = name[index+1:]
	}
	return namespace, name
}

func purlType(t string) string {
	switch t {
	case string(analyzer.TypeJar), string(analyzer.TypePom):
		return packageurl.TypeMaven
	case string(analyzer.TypeBundler), string(analyzer.TypeGemSpec):
		return packageurl.TypeGem
	case string(analyzer.TypePythonPkg), string(analyzer.TypePip), string(analyzer.TypePipenv), string(analyzer.TypePoetry):
		return packageurl.TypePyPi
	case string(analyzer.TypeGoBinary), string(analyzer.TypeGoMod):
		return packageurl.TypeGolang
	case string(analyzer.TypeNpmPkgLock), string(analyzer.TypeNodePkg), string(analyzer.TypeYarn):
		return packageurl.TypeNPM
	case os.Alpine:
		return string(analyzer.TypeApk)
	case os.Debian, os.Ubuntu:
		return packageurl.TypeDebian
	case os.RedHat, os.CentOS, os.Rocky, os.Alma,
		os.Amazon, os.Fedora, os.Oracle, os.OpenSUSE,
		os.OpenSUSELeap, os.OpenSUSETumbleweed, os.SLES, os.Photon:
		return packageurl.TypeRPM
	}
	return t
}

func parseQualifier(pkg types.Package, distro string) packageurl.Qualifiers {
	qualifiers := packageurl.Qualifiers{}
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	if pkg.Epoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "epoch",
			Value: strconv.Itoa(pkg.Epoch),
		})
	}
	return qualifiers
}

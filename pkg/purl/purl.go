package purl

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"

	"github.com/package-url/packageurl-go"
)

func NewPackageURL(t string, class report.ResultClass, fos types.OS, pkg types.Package) packageurl.PackageURL {
	var purl *packageurl.PackageURL

	switch class {
	case report.ClassOSPkg:
		qualifiers := parseQualifier(pkg, fos.Name)
		family := fos.Family
		version := fmt.Sprintf("%s-%s", pkg.Version, pkg.Release)

		// SLES string has whitespace
		if fos.Family == os.SLES {
			family = "sles"
		}

		purl = packageurl.NewPackageURL(purlType(t), family, pkg.Name, version, qualifiers, "")
	case report.ClassLangPkg:
		name := pkg.Name
		namespace := ""
		switch t {
		case string(analyzer.TypeJar), string(analyzer.TypePom):
			namespace, name = parseMaven(name)
		case string(analyzer.TypePythonPkg), string(analyzer.TypePip), string(analyzer.TypePipenv), string(analyzer.TypePoetry):
			name = parsePyPI(name)
		case string(analyzer.TypeComposer):
			namespace, name = parseComposer(name)
		case string(analyzer.TypeGoBinary), string(analyzer.TypeGoMod):
			namespace, name = parseGolang(name)
		case string(analyzer.TypeNpmPkgLock), string(analyzer.TypeNodePkg), string(analyzer.TypeYarn):
			namespace, name = parseNpm(name)
		}

		purl = packageurl.NewPackageURL(purlType(t), namespace, name, pkg.Version, nil, "")
	}

	return *purl
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
		return string(analyzer.TypeDpkg)
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
	if distro != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "distro",
			Value: distro,
		})
	}
	if pkg.FilePath != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "file_path",
			Value: pkg.FilePath,
		})
	}
	if pkg.Modularitylabel != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "modularitylabel",
			Value: pkg.Modularitylabel,
		})
	}
	if pkg.SrcName != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_name",
			Value: pkg.SrcName,
		})
	}
	if pkg.SrcEpoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_epoch",
			Value: strconv.Itoa(pkg.SrcEpoch),
		})
	}
	if pkg.SrcRelease != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_release",
			Value: pkg.SrcRelease,
		})
	}
	if pkg.SrcVersion != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_version",
			Value: pkg.SrcVersion,
		})
	}
	return qualifiers
}

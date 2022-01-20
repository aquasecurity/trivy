package purl

import (
	"strconv"
	"strings"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"

	"github.com/package-url/packageurl-go"
)

func NewOSPackageURL(t string, fos types.OS, pkg types.Package) packageurl.PackageURL {
	qualifiers := parseQualifier(pkg)
	qualifiers = append(qualifiers, packageurl.Qualifier{
		Key:   "distro",
		Value: fos.Name,
	})
	family := fos.Family

	// SLES string has whitespace
	if fos.Family == os.SLES {
		family = "sles"
	}

	return *packageurl.NewPackageURL(purlType(t), family, pkg.Name, pkg.Version, qualifiers, "")
}

func NewPackageURL(t string, pkg types.Package) packageurl.PackageURL {
	name := strings.ReplaceAll(pkg.Name, ":", "/")
	index := strings.LastIndex(name, "/")

	namespace := ""

	pkgName := name
	if index != -1 {
		namespace = name[:index]
		pkgName = name[index+1:]
	}
	purl := packageurl.NewPackageURL(purlType(t), namespace, pkgName, pkg.Version, nil, "")

	return *purl
}

func purlType(t string) string {
	switch t {
	case string(analyzer.TypeJar):
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

func parseQualifier(pkg types.Package) packageurl.Qualifiers {
	qualifiers := packageurl.Qualifiers{}
	if pkg.Release != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "release",
			Value: pkg.Release,
		})
	}
	if pkg.Epoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "epoch",
			Value: strconv.Itoa(pkg.Epoch),
		})
	}
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	if pkg.SrcName != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_name",
			Value: pkg.SrcName,
		})
	}
	if pkg.SrcVersion != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_version",
			Value: pkg.SrcVersion,
		})
	}
	if pkg.SrcRelease != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_release",
			Value: pkg.SrcRelease,
		})
	}
	if pkg.SrcEpoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "src_epoch",
			Value: strconv.Itoa(pkg.SrcEpoch),
		})
	}
	if pkg.Modularitylabel != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "modularitylabel",
			Value: pkg.Modularitylabel,
		})
	}
	if pkg.FilePath != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "file_path",
			Value: pkg.FilePath,
		})
	}
	return qualifiers
}

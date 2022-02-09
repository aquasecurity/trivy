package purl

import (
	"fmt"
	"strconv"
	"strings"

	cn "github.com/google/go-containerregistry/pkg/name"
	"github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	"github.com/aquasecurity/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	TypeOCI = "oci"
)

// nolint: gocyclo
func NewPackageURL(t string, metadata types.Metadata, pkg ftypes.Package) (packageurl.PackageURL, error) {
	ptype := purlType(t)

	var qualifiers packageurl.Qualifiers
	if metadata.OS != nil {
		qualifiers = parseQualifier(pkg, metadata.OS.Name)
	}

	name := pkg.Name
	version := utils.FormatVersion(pkg)
	namespace := ""

	switch ptype {
	case packageurl.TypeRPM:
		ns, qs := parseRPM(metadata.OS, pkg.Modularitylabel)
		namespace = ns
		qualifiers = append(qualifiers, qs...)
	case packageurl.TypeDebian:
		qualifiers = append(qualifiers, parseDeb(metadata.OS)...)
		namespace = metadata.OS.Family
	case string(analyzer.TypeApk): // TODO: replace with packageurl.TypeApk
		qualifiers = append(qualifiers, parseApk(metadata.OS)...)
		namespace = metadata.OS.Family
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
	case packageurl.TypeOCI:
		return parseOCI(metadata)
	}

	return *packageurl.NewPackageURL(ptype, namespace, name, version, qualifiers, ""), nil
}

func parseOCI(metadata types.Metadata) (packageurl.PackageURL, error) {
	if len(metadata.RepoDigests) == 0 {
		return packageurl.PackageURL{}, xerrors.New("repository digests empty error")
	}

	digest, err := cn.NewDigest(metadata.RepoDigests[0])
	if err != nil {
		return packageurl.PackageURL{}, xerrors.Errorf("failed to parse digest: %w", err)
	}

	name := strings.ToLower(digest.RepositoryStr())
	index := strings.LastIndex(name, "/")
	if index != -1 {
		name = name[index+1:]
	}
	qualifiers := packageurl.Qualifiers{
		packageurl.Qualifier{
			Key:   "repository_url",
			Value: digest.Repository.Name(),
		},
		packageurl.Qualifier{
			Key:   "arch",
			Value: metadata.ImageConfig.Architecture,
		},
	}

	return *packageurl.NewPackageURL(packageurl.TypeOCI, "", name, digest.DigestStr(), qualifiers, ""), nil
}

func parseApk(fos *ftypes.OS) packageurl.Qualifiers {
	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fos.Name,
		},
	}
}

func parseDeb(fos *ftypes.OS) packageurl.Qualifiers {
	distro := fmt.Sprintf("%s-%s", fos.Family, fos.Name)
	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: distro,
		},
	}
}

func parseRPM(fos *ftypes.OS, modularityLabel string) (string, packageurl.Qualifiers) {
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
	case TypeOCI:
		return packageurl.TypeOCI
	}
	return t
}

func parseQualifier(pkg ftypes.Package, distro string) packageurl.Qualifiers {
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

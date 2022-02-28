package purl

import (
	"fmt"
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

type PackageURL struct {
	packageurl.PackageURL
	FilePath string
}

func (purl PackageURL) BOMRef() string {
	// 'bom-ref' must be unique within BOM, but PURLs may conflict
	// when the same packages are installed in an artifact.
	// In that case, we prefer to make PURLs unique by adding file paths,
	// rather than using UUIDs, even if it is not PURL technically.
	// ref. https://cyclonedx.org/use-cases/#dependency-graph
	if purl.FilePath != "" {
		purl.Qualifiers = append(purl.Qualifiers,
			packageurl.Qualifier{
				Key:   "file_path",
				Value: purl.FilePath,
			},
		)
	}
	return purl.PackageURL.String()
}

// nolint: gocyclo
func NewPackageURL(t string, metadata types.Metadata, pkg ftypes.Package) (PackageURL, error) {
	var qualifiers packageurl.Qualifiers
	if metadata.OS != nil {
		qualifiers = parseQualifier(pkg)
	}

	ptype := purlType(t)
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
		if metadata.OS != nil {
			namespace = metadata.OS.Family
		}
	case string(analyzer.TypeApk): // TODO: replace with packageurl.TypeApk once they add it.
		qualifiers = append(qualifiers, parseApk(metadata.OS)...)
		if metadata.OS != nil {
			namespace = metadata.OS.Family
		}
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
		purl, err := parseOCI(metadata)
		if err != nil {
			return PackageURL{}, err
		}
		return PackageURL{PackageURL: purl}, nil
	}

	return PackageURL{
		PackageURL: *packageurl.NewPackageURL(ptype, namespace, name, version, qualifiers, ""),
		FilePath:   pkg.FilePath,
	}, nil
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#oci
func parseOCI(metadata types.Metadata) (packageurl.PackageURL, error) {
	if len(metadata.RepoDigests) == 0 {
		return *packageurl.NewPackageURL("", "", "", "", nil, ""), nil
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
	if fos == nil {
		return packageurl.Qualifiers{}
	}

	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fos.Name,
		},
	}
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#deb
func parseDeb(fos *ftypes.OS) packageurl.Qualifiers {

	if fos == nil {
		return packageurl.Qualifiers{}
	}

	distro := fmt.Sprintf("%s-%s", fos.Family, fos.Name)
	return packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: distro,
		},
	}
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#rpm
func parseRPM(fos *ftypes.OS, modularityLabel string) (string, packageurl.Qualifiers) {
	if fos == nil {
		return "", packageurl.Qualifiers{}
	}

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

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#maven
func parseMaven(pkgName string) (string, string) {
	// The group id is the "namespace" and the artifact id is the "name".
	name := strings.ReplaceAll(pkgName, ":", "/")
	return parsePkgName(name)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#golang
func parseGolang(pkgName string) (string, string) {
	name := strings.ToLower(pkgName)
	return parsePkgName(name)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#pypi
func parsePyPI(pkgName string) string {
	// PyPi treats - and _ as the same character and is not case-sensitive.
	// Therefore a Pypi package name must be lowercased and underscore "_" replaced with a dash "-".
	return strings.ToLower(strings.ReplaceAll(pkgName, "_", "-"))
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#composer
func parseComposer(pkgName string) (string, string) {
	return parsePkgName(pkgName)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#npm
func parseNpm(pkgName string) (string, string) {
	// the name must be lowercased
	name := strings.ToLower(pkgName)
	return parsePkgName(name)
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

func parseQualifier(pkg ftypes.Package) packageurl.Qualifiers {
	qualifiers := packageurl.Qualifiers{}
	if pkg.Arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: pkg.Arch,
		})
	}
	return qualifiers
}

func parsePkgName(name string) (string, string) {
	var namespace string
	index := strings.LastIndex(name, "/")
	if index != -1 {
		namespace = name[:index]
		name = name[index+1:]
	}
	return namespace, name

}

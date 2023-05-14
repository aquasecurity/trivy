package purl

import (
	"fmt"
	"strconv"
	"strings"

	cn "github.com/google/go-containerregistry/pkg/name"
	version "github.com/knqyf263/go-rpm-version"
	packageurl "github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	TypeAPK  = "apk" // not defined in github.com/package-url/packageurl-go
	TypeOCI  = "oci"
	TypeDart = "dart"
)

type PackageURL struct {
	packageurl.PackageURL
	FilePath string
}

func FromString(purl string) (*PackageURL, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl(%s): %w", purl, err)
	}

	return &PackageURL{
		PackageURL: p,
	}, nil
}

func (p *PackageURL) Package() *ftypes.Package {
	pkg := &ftypes.Package{
		Name:    p.Name,
		Version: p.Version,
	}
	for _, q := range p.Qualifiers {
		switch q.Key {
		case "arch":
			pkg.Arch = q.Value
		case "modularitylabel":
			pkg.Modularitylabel = q.Value
		case "epoch":
			epoch, err := strconv.Atoi(q.Value)
			if err == nil {
				pkg.Epoch = epoch
			}
		}
	}

	if p.Type == packageurl.TypeRPM {
		rpmVer := version.NewVersion(p.Version)
		pkg.Release = rpmVer.Release()
		pkg.Version = rpmVer.Version()
	}

	// Return packages without namespace.
	// OS packages are not supposed to have namespace.
	if p.Namespace == "" || p.IsOSPkg() {
		return pkg
	}

	// TODO: replace with packageurl.TypeGradle once they add it.
	if p.Type == packageurl.TypeMaven || p.Type == ftypes.Gradle {
		// Maven and Gradle packages separate ":"
		// e.g. org.springframework:spring-core
		pkg.Name = strings.Join([]string{p.Namespace, p.Name}, ":")
	} else {
		pkg.Name = strings.Join([]string{p.Namespace, p.Name}, "/")
	}

	return pkg
}

// PackageType returns an application type in Trivy
func (p *PackageURL) PackageType() string {
	switch p.Type {
	case packageurl.TypeComposer:
		return ftypes.Composer
	case packageurl.TypeMaven:
		return ftypes.Jar
	case packageurl.TypeGem:
		return ftypes.GemSpec
	case packageurl.TypeConda:
		return ftypes.CondaPkg
	case packageurl.TypePyPi:
		return ftypes.PythonPkg
	case packageurl.TypeGolang:
		return ftypes.GoBinary
	case packageurl.TypeNPM:
		return ftypes.NodePkg
	case packageurl.TypeCargo:
		return ftypes.Cargo
	case packageurl.TypeNuget:
		return ftypes.NuGet
	case packageurl.TypeSwift:
		return ftypes.Cocoapods
	case packageurl.TypeHex:
		return ftypes.Hex
	case TypeDart: // TODO: replace with packageurl.TypeDart once they add it.
		return ftypes.Pub
	}
	return p.Type
}

func (p *PackageURL) IsOSPkg() bool {
	return p.Type == TypeAPK || p.Type == packageurl.TypeDebian || p.Type == packageurl.TypeRPM
}

func (p *PackageURL) BOMRef() string {
	// 'bom-ref' must be unique within BOM, but PURLs may conflict
	// when the same packages are installed in an artifact.
	// In that case, we prefer to make PURLs unique by adding file paths,
	// rather than using UUIDs, even if it is not PURL technically.
	// ref. https://cyclonedx.org/use-cases/#dependency-graph
	purl := p.PackageURL // so that it will not override the qualifiers below
	if p.FilePath != "" {
		purl.Qualifiers = append(purl.Qualifiers,
			packageurl.Qualifier{
				Key:   "file_path",
				Value: p.FilePath,
			},
		)
	}
	return purl.String()
}

// nolint: gocyclo
func NewPackageURL(t string, metadata types.Metadata, pkg ftypes.Package) (PackageURL, error) {
	var qualifiers packageurl.Qualifiers
	if metadata.OS != nil {
		qualifiers = parseQualifier(pkg)
		pkg.Epoch = 0 // we moved Epoch to qualifiers so we don't need it in version
	}

	ptype := purlType(t)
	name := pkg.Name
	ver := utils.FormatVersion(pkg)
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
	case TypeAPK: // TODO: replace with packageurl.TypeApk once they add it.
		qualifiers = append(qualifiers, parseApk(metadata.OS)...)
		if metadata.OS != nil {
			namespace = metadata.OS.Family
		}
	case packageurl.TypeMaven, string(ftypes.Gradle): // TODO: replace with packageurl.TypeGradle once they add it.
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
		PackageURL: *packageurl.NewPackageURL(ptype, namespace, name, ver, qualifiers, ""),
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

	qualifiers := packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fmt.Sprintf("%s-%s", family, fos.Name),
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
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle:
		return packageurl.TypeMaven
	case ftypes.Bundler, ftypes.GemSpec:
		return packageurl.TypeGem
	case ftypes.NuGet, ftypes.DotNetCore:
		return packageurl.TypeNuget
	case ftypes.CondaPkg:
		return packageurl.TypeConda
	case ftypes.PythonPkg, ftypes.Pip, ftypes.Pipenv, ftypes.Poetry:
		return packageurl.TypePyPi
	case ftypes.GoBinary, ftypes.GoModule:
		return packageurl.TypeGolang
	case ftypes.Npm, ftypes.NodePkg, ftypes.Yarn, ftypes.Pnpm:
		return packageurl.TypeNPM
	case ftypes.Cocoapods:
		return packageurl.TypeSwift
	case ftypes.Hex:
		return packageurl.TypeHex
	case ftypes.Pub:
		return TypeDart // TODO: replace with packageurl.TypeDart once they add it.
	case os.Alpine:
		return TypeAPK
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
	if pkg.Epoch != 0 {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "epoch",
			Value: strconv.Itoa(pkg.Epoch),
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

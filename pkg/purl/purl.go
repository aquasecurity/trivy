package purl

import (
	"fmt"
	"strings"

	cn "github.com/google/go-containerregistry/pkg/name"
	version "github.com/knqyf263/go-rpm-version"
	packageurl "github.com/package-url/packageurl-go"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/fanal/analyzer"
	"github.com/aquasecurity/trivy/pkg/fanal/analyzer/os"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
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

func FromString(purl string) (*PackageURL, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl: %w", err)
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
		}
	}

	if p.Type == packageurl.TypeRPM {
		rpmVer := version.NewVersion(p.Version)
		pkg.Release = rpmVer.Release()
		pkg.Version = rpmVer.Version()
		pkg.Epoch = rpmVer.Epoch()
	}

	// TODO: replace with packageurl.TypeApk once they add it.
	// Return of packages without Namespace.
	// OS packages does not have namespace.
	if p.Namespace == "" || p.Type == packageurl.TypeRPM || p.Type == packageurl.TypeDebian || p.Type == string(analyzer.TypeApk) {
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

// AppType returns an application type in Trivy
func (p *PackageURL) AppType() string {
	switch p.Type {
	case packageurl.TypeComposer:
		return string(analyzer.TypeComposer)
	case packageurl.TypeMaven:
		return string(analyzer.TypeJar)
	case packageurl.TypeGem:
		return string(analyzer.TypeGemSpec)
	case packageurl.TypePyPi:
		return string(analyzer.TypePythonPkg)
	case packageurl.TypeGolang:
		return string(analyzer.TypeGoBinary)
	case packageurl.TypeNPM:
		return string(analyzer.TypeNodePkg)
	case packageurl.TypeCargo:
		return string(analyzer.TypeRustBinary)
	case packageurl.TypeNuget:
		return string(analyzer.TypeNuget)
	}
	return p.Type
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
	case string(analyzer.TypeApk): // TODO: replace with packageurl.TypeApk once they add it.
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
	case string(analyzer.TypeJar), string(analyzer.TypePom):
		return packageurl.TypeMaven
	case string(analyzer.TypeBundler), string(analyzer.TypeGemSpec):
		return packageurl.TypeGem
	case string(analyzer.TypeNuget), string(analyzer.TypeDotNetCore):
		return packageurl.TypeNuget
	case string(analyzer.TypePythonPkg), string(analyzer.TypePip), string(analyzer.TypePipenv), string(analyzer.TypePoetry):
		return packageurl.TypePyPi
	case string(analyzer.TypeGoBinary), string(analyzer.TypeGoMod):
		return packageurl.TypeGolang
	case string(analyzer.TypeNpmPkgLock), string(analyzer.TypeNodePkg), string(analyzer.TypeYarn), string(analyzer.TypePnpm):
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

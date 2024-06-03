package purl

import (
	"fmt"
	"strconv"
	"strings"

	cn "github.com/google/go-containerregistry/pkg/name"
	version "github.com/knqyf263/go-rpm-version"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/samber/lo"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/dependency"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	TypeOCI = "oci"

	// TypeK8s is a custom type for Kubernetes components in PURL.
	//  - namespace: The service provider such as EKS or GKE. It is not case sensitive and must be lowercased.
	//     Known namespaces:
	//       - empty (upstream)
	//       - eks (AWS)
	//       - aks (GCP)
	//       - gke (Azure)
	//       - rke (Rancher)
	//  - name: The k8s component name and is case sensitive.
	//  - version: The combined version and release of a component.
	//
	//  Examples:
	//    - pkg:k8s/upstream/k8s.io%2Fapiserver@1.24.1
	//    - pkg:k8s/eks/k8s.io%2Fkube-proxy@1.26.2-eksbuild.1
	TypeK8s = "k8s"

	NamespaceEKS = "eks"
	NamespaceAKS = "aks"
	NamespaceGKE = "gke"
	NamespaceOCP = "ocp"

	TypeUnknown = "unknown"
)

type PackageURL packageurl.PackageURL

func FromString(s string) (*PackageURL, error) {
	p, err := packageurl.FromString(s)
	if err != nil {
		return nil, xerrors.Errorf("failed to parse purl(%s): %w", s, err)
	}

	if len(p.Qualifiers) == 0 {
		p.Qualifiers = nil
	}

	return lo.ToPtr(PackageURL(p)), nil
}

// nolint: gocyclo
func New(t ftypes.TargetType, metadata types.Metadata, pkg ftypes.Package) (*PackageURL, error) {
	qualifiers := parseQualifier(pkg)
	pkg.Epoch = 0 // we moved Epoch to qualifiers so we don't need it in version

	ptype := purlType(t)
	name := pkg.Name
	ver := utils.FormatVersion(pkg)
	namespace := ""
	subpath := ""

	switch ptype {
	case packageurl.TypeRPM:
		ns, qs := parseRPM(metadata.OS, pkg.Modularitylabel)
		namespace = string(ns)
		qualifiers = append(qualifiers, qs...)
	case packageurl.TypeDebian:
		qualifiers = append(qualifiers, parseDeb(metadata.OS)...)
		if metadata.OS != nil {
			namespace = string(metadata.OS.Family)
		}
	case packageurl.TypeApk:
		var qs packageurl.Qualifiers
		name, namespace, qs = parseApk(name, metadata.OS)
		qualifiers = append(qualifiers, qs...)
	case packageurl.TypeMaven, string(ftypes.Gradle): // TODO: replace with packageurl.TypeGradle once they add it.
		namespace, name = parseMaven(name)
	case packageurl.TypePyPi:
		name = parsePyPI(name)
	case packageurl.TypeComposer:
		namespace, name = parseComposer(name)
	case packageurl.TypeGolang:
		namespace, name = parseGolang(name)
		if name == "" {
			return nil, nil
		}
	case packageurl.TypeNPM:
		namespace, name = parseNpm(name)
	case packageurl.TypeSwift:
		namespace, name = parseSwift(name)
	case packageurl.TypeCocoapods:
		name, subpath = parseCocoapods(name)
	case packageurl.TypeOCI:
		purl, err := parseOCI(metadata)
		if err != nil {
			return nil, err
		} else if purl == nil {
			return nil, nil
		}
		return (*PackageURL)(purl), nil
	}

	return (*PackageURL)(packageurl.NewPackageURL(ptype, namespace, name, ver, qualifiers, subpath)), nil
}

func (p *PackageURL) Unwrap() *packageurl.PackageURL {
	if p == nil {
		return nil
	}
	purl := (*packageurl.PackageURL)(p)
	if len(purl.Qualifiers) == 0 {
		purl.Qualifiers = nil
	}
	return purl
}

// LangType returns an application type in Trivy
// nolint: gocyclo
func (p *PackageURL) LangType() ftypes.LangType {
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
		return ftypes.Swift
	case packageurl.TypeCocoapods:
		return ftypes.Cocoapods
	case packageurl.TypeHex:
		return ftypes.Hex
	case packageurl.TypeConan:
		return ftypes.Conan
	case packageurl.TypePub:
		return ftypes.Pub
	case packageurl.TypeBitnami:
		return ftypes.Bitnami
	case TypeK8s:
		switch p.Namespace {
		case NamespaceEKS:
			return ftypes.EKS
		case NamespaceGKE:
			return ftypes.GKE
		case NamespaceAKS:
			return ftypes.AKS
		case NamespaceOCP:
			return ftypes.OCP
		case "":
			return ftypes.K8sUpstream
		}
		return TypeUnknown
	default:
		return TypeUnknown
	}
}

func (p *PackageURL) Class() types.ResultClass {
	switch p.Type {
	case packageurl.TypeApk, packageurl.TypeDebian, packageurl.TypeRPM:
		// OS packages
		return types.ClassOSPkg
	default:
		if p.LangType() == TypeUnknown {
			return types.ClassUnknown
		}
		// Language-specific packages
		return types.ClassLangPkg
	}
}

func (p *PackageURL) Package() *ftypes.Package {
	pkgName := p.Name
	if p.Namespace != "" && p.Class() != types.ClassOSPkg {
		if p.Type == packageurl.TypeMaven || p.Type == packageurl.TypeGradle {
			// Maven and Gradle packages separate ":"
			// e.g. org.springframework:spring-core
			pkgName = p.Namespace + ":" + p.Name
		} else {
			pkgName = p.Namespace + "/" + p.Name
		}
	}

	// CocoaPods purl has no namespace, but has subpath
	// https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#cocoapods
	if p.Subpath != "" && p.Type == packageurl.TypeCocoapods {
		// CocoaPods uses <moduleName>/<submoduleName> format for package name
		// e.g. `pkg:cocoapods/GoogleUtilities@7.5.2#NSData+zlib` => `GoogleUtilities/NSData+zlib`
		pkgName = p.Name + "/" + p.Subpath
	}

	pkg := &ftypes.Package{
		ID:      dependency.ID(p.LangType(), pkgName, p.Version),
		Name:    pkgName,
		Version: p.Version,
		Identifier: ftypes.PkgIdentifier{
			PURL: p.Unwrap(),
		},
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

	return pkg
}

// Match returns true if the given PURL "target" satisfies the constraint PURL "p".
// - If the constraint does not have a version, it will match any version in the target.
// - If the constraint has qualifiers, the target must have the same set of qualifiers to match.
func (p *PackageURL) Match(target *packageurl.PackageURL) bool {
	if target == nil {
		return false
	}
	switch {
	case p.Type != target.Type:
		return false
	case p.Namespace != target.Namespace:
		return false
	case p.Name != target.Name:
		return false
	case p.Version != "" && p.Version != target.Version:
		return false
	case p.Subpath != "" && p.Subpath != target.Subpath:
		return false
	}

	// All qualifiers in the constraint must be in the target to match
	q := target.Qualifiers.Map()
	for k, v1 := range p.Qualifiers.Map() {
		if v2, ok := q[k]; !ok || v1 != v2 {
			return false
		}
	}
	return true
}

func (p *PackageURL) String() string {
	return p.Unwrap().String()
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#oci
func parseOCI(metadata types.Metadata) (*packageurl.PackageURL, error) {
	if len(metadata.RepoDigests) == 0 {
		return nil, nil
	}

	digest, err := cn.NewDigest(metadata.RepoDigests[0])
	if err != nil {
		return nil, xerrors.Errorf("failed to parse digest: %w", err)
	}

	name := strings.ToLower(digest.RepositoryStr())
	index := strings.LastIndex(name, "/")
	if index != -1 {
		name = name[index+1:]
	}

	var qualifiers packageurl.Qualifiers
	if repoURL := digest.Repository.Name(); repoURL != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "repository_url",
			Value: repoURL,
		})
	}
	if arch := metadata.ImageConfig.Architecture; arch != "" {
		qualifiers = append(qualifiers, packageurl.Qualifier{
			Key:   "arch",
			Value: metadata.ImageConfig.Architecture,
		})
	}

	return packageurl.NewPackageURL(packageurl.TypeOCI, "", name, digest.DigestStr(), qualifiers, ""), nil
}

// ref. https://github.com/package-url/purl-spec/blob/master/PURL-TYPES.rst#apk
func parseApk(pkgName string, fos *ftypes.OS) (string, string, packageurl.Qualifiers) {
	// the name must be lowercase
	pkgName = strings.ToLower(pkgName)

	if fos == nil {
		return pkgName, "", nil
	}

	// the namespace must be lowercase
	ns := strings.ToLower(string(fos.Family))
	qs := packageurl.Qualifiers{
		{
			Key:   "distro",
			Value: fos.Name,
		},
	}

	return pkgName, ns, qs
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
func parseRPM(fos *ftypes.OS, modularityLabel string) (ftypes.OSType, packageurl.Qualifiers) {
	if fos == nil {
		return "", packageurl.Qualifiers{}
	}

	// SLES string has whitespace
	family := fos.Family
	if fos.Family == ftypes.SLES {
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
	// The PURL will be skipped when the package name is a local path, since it can't identify a software package.
	if strings.HasPrefix(pkgName, "./") || strings.HasPrefix(pkgName, "../") {
		return "", ""
	}
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

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#swift
func parseSwift(pkgName string) (string, string) {
	return parsePkgName(pkgName)
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#cocoapods
func parseCocoapods(pkgName string) (string, string) {
	var subpath string
	pkgName, subpath, _ = strings.Cut(pkgName, "/")
	return pkgName, subpath
}

// ref. https://github.com/package-url/purl-spec/blob/a748c36ad415c8aeffe2b8a4a5d8a50d16d6d85f/PURL-TYPES.rst#npm
func parseNpm(pkgName string) (string, string) {
	// the name must be lowercased
	name := strings.ToLower(pkgName)
	return parsePkgName(name)
}

func purlType(t ftypes.TargetType) string {
	switch t {
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle:
		return packageurl.TypeMaven
	case ftypes.Bundler, ftypes.GemSpec:
		return packageurl.TypeGem
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
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
		return packageurl.TypeCocoapods
	case ftypes.Swift:
		return packageurl.TypeSwift
	case ftypes.Hex:
		return packageurl.TypeHex
	case ftypes.Conan:
		return packageurl.TypeConan
	case ftypes.Pub:
		return packageurl.TypePub
	case ftypes.RustBinary, ftypes.Cargo:
		return packageurl.TypeCargo
	case ftypes.Alpine:
		return packageurl.TypeApk
	case ftypes.Debian, ftypes.Ubuntu:
		return packageurl.TypeDebian
	case ftypes.RedHat, ftypes.CentOS, ftypes.Rocky, ftypes.Alma,
		ftypes.Amazon, ftypes.Fedora, ftypes.Oracle, ftypes.OpenSUSE,
		ftypes.OpenSUSELeap, ftypes.OpenSUSETumbleweed, ftypes.SLES, ftypes.Photon:
		return packageurl.TypeRPM
	case ftypes.PythonExecutable, ftypes.PhpExecutable, ftypes.NodeJsExecutable:
		return packageurl.TypeGeneric
	case TypeOCI:
		return packageurl.TypeOCI
	}
	return string(t)
}

func parseQualifier(pkg ftypes.Package) packageurl.Qualifiers {
	var qualifiers packageurl.Qualifiers
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

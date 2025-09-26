package rootio

import (
	"regexp"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	// rootIOPattern matches generic Root.io version pattern: .root.io
	rootIOPattern = regexp.MustCompile(`\.root\.io`)
)

// DriverInterface defines the interface that library.Driver must satisfy
type DriverInterface interface {
	Type() string
	DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error)
}

// Provider creates a Root.io driver if Root.io packages are detected
// It returns nil if conditions are not met, which will be interpreted as an empty driver
func Provider(libType ftypes.LangType, pkgs []ftypes.Package) interface{} {
	ecosystem, ok := getEcosystem(libType)
	if !ok || !isRootIOEnvironment(pkgs) {
		return nil
	}

	comparer := getComparerForEcosystem(ecosystem)
	return NewScanner(ecosystem, comparer)
}

// getEcosystem maps language type to ecosystem
func getEcosystem(libType ftypes.LangType) (dbTypes.Ecosystem, bool) {
	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		return vulnerability.RubyGems, true
	case ftypes.RustBinary, ftypes.Cargo:
		return vulnerability.Cargo, true
	case ftypes.Composer, ftypes.ComposerVendor:
		return vulnerability.Composer, true
	case ftypes.GoBinary, ftypes.GoModule:
		return vulnerability.Go, true
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		return vulnerability.Maven, true
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.Bun, ftypes.NodePkg, ftypes.JavaScript:
		return vulnerability.Npm, true
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		return vulnerability.NuGet, true
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg, ftypes.Uv:
		return vulnerability.Pip, true
	case ftypes.Pub:
		return vulnerability.Pub, true
	case ftypes.Hex:
		return vulnerability.Erlang, true
	case ftypes.Conan:
		return vulnerability.Conan, true
	case ftypes.Swift:
		return vulnerability.Swift, true
	case ftypes.Cocoapods:
		return vulnerability.Cocoapods, true
	case ftypes.Bitnami:
		return vulnerability.Bitnami, true
	case ftypes.K8sUpstream:
		return vulnerability.Kubernetes, true
	default:
		return "", false
	}
}

// isRootIOEnvironment detects if the environment contains Root.io packages
func isRootIOEnvironment(pkgs []ftypes.Package) bool {
	return hasPackageWithPattern(pkgs, rootIOPattern)
}

// hasPackageWithPattern checks if any package version matches the specified pattern
func hasPackageWithPattern(pkgs []ftypes.Package, pattern *regexp.Regexp) bool {
	for _, pkg := range pkgs {
		if pattern.MatchString(pkg.Version) {
			return true
		}
	}
	return false
}

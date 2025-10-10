package rootio

import (
	"regexp"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	rootIOPattern = regexp.MustCompile(`root\.io`)
)

// Provider creates Root.io driver functions if Root.io packages are detected
// It returns nil functions if conditions are not met
func Provider(libType ftypes.LangType, pkgs []ftypes.Package) (func() string, func(string, string, string) ([]types.DetectedVulnerability, error)) {
	eco, ok := getEcosystem(libType)
	if !ok || !isRootIOEnvironment(pkgs) {
		return nil, nil
	}

	comparer := getComparerForEcosystem(eco)
	scanner := NewScanner(eco, comparer)
	
	// Return the scanner's methods as functions
	return scanner.Type, scanner.DetectVulnerabilities
}

// getEcosystem maps language type to ecosystem
func getEcosystem(libType ftypes.LangType) (ecosystem.Type, bool) {
	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		return ecosystem.RubyGems, true
	case ftypes.RustBinary, ftypes.Cargo:
		return ecosystem.Cargo, true
	case ftypes.Composer, ftypes.ComposerVendor:
		return ecosystem.Composer, true
	case ftypes.GoBinary, ftypes.GoModule:
		return ecosystem.Go, true
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		return ecosystem.Maven, true
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.Bun, ftypes.NodePkg, ftypes.JavaScript:
		return ecosystem.Npm, true
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		return ecosystem.NuGet, true
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg, ftypes.Uv:
		return ecosystem.Pip, true
	case ftypes.Pub:
		return ecosystem.Pub, true
	case ftypes.Hex:
		return ecosystem.Erlang, true
	case ftypes.Conan:
		return ecosystem.Conan, true
	case ftypes.Swift:
		return ecosystem.Swift, true
	case ftypes.Cocoapods:
		return ecosystem.Cocoapods, true
	case ftypes.Bitnami:
		return ecosystem.Bitnami, true
	case ftypes.K8sUpstream:
		return ecosystem.Kubernetes, true
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

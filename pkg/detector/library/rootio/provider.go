package rootio

import (
	"regexp"

	"github.com/aquasecurity/trivy-db/pkg/ecosystem"
	"github.com/aquasecurity/trivy/pkg/detector/library/driver"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
)

var (
	rootIOPattern = regexp.MustCompile(`root\.io`)
)

// Provider creates Root.io driver functions if Root.io packages are detected
// It returns nil functions if conditions are not met
func Provider(libType ftypes.LangType, pkgs []ftypes.Package) driver.Driver {
	eco := langTypeToEcosystem(libType)

	// Unsupported Root.io ecosystem
	if eco == "" {
		return nil
	}

	// Check if the environment contains Root.io packages
	if !isRootIOEnvironment(pkgs) {
		return nil
	}

	return NewScanner(eco)
}

func langTypeToEcosystem(libType ftypes.LangType) ecosystem.Type {
	switch libType {
	case ftypes.Bundler, ftypes.GemSpec:
		return ecosystem.RubyGems
	case ftypes.RustBinary, ftypes.Cargo:
		return ecosystem.Cargo
	case ftypes.GoBinary, ftypes.GoModule:
		return ecosystem.Go
	case ftypes.Jar, ftypes.Pom, ftypes.Gradle, ftypes.Sbt:
		return ecosystem.Maven
	case ftypes.Npm, ftypes.Yarn, ftypes.Pnpm, ftypes.Bun, ftypes.NodePkg, ftypes.JavaScript:
		return ecosystem.Npm
	case ftypes.NuGet, ftypes.DotNetCore, ftypes.PackagesProps:
		return ecosystem.NuGet
	case ftypes.Pipenv, ftypes.Poetry, ftypes.Pip, ftypes.PythonPkg, ftypes.Uv:
		return ecosystem.Pip
	default:
		return ""
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

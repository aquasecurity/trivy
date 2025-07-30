package rego

import (
	"github.com/open-policy-agent/opa/v1/ast"

	"github.com/aquasecurity/go-version/pkg/semver"
	"github.com/aquasecurity/trivy/pkg/iac/framework"
	"github.com/aquasecurity/trivy/pkg/log"
)

type RegoModuleFilter func(module *ast.Module, metadata *StaticMetadata) bool

// TrivyVersionFilter returns a filter that allows only those modules,
// that are compatible with the given version of Trivy.
func TrivyVersionFilter(trivyVer string) RegoModuleFilter {
	if trivyVer == "dev" {
		return func(_ *ast.Module, _ *StaticMetadata) bool {
			return true
		}
	}

	tv, tverr := semver.Parse(trivyVer)
	if tverr != nil {
		log.Warn(
			"Failed to parse Trivy version - cannot confirm if all modules will work with current version",
			log.Prefix("rego"),
			log.String("trivy_version", trivyVer),
			log.Err(tverr),
		)
		return func(_ *ast.Module, _ *StaticMetadata) bool {
			return true
		}
	}
	return func(module *ast.Module, metadata *StaticMetadata) bool {
		return isMinimumVersionSupported(metadata, module, tv)
	}
}

func isMinimumVersionSupported(metadata *StaticMetadata, module *ast.Module, tv semver.Version) bool {
	// to ensure compatibility with old modules without minimum trivy version
	if metadata.MinimumTrivyVersion == "" {
		return true
	}

	mmsv, err := semver.Parse(metadata.MinimumTrivyVersion)
	if err != nil {
		log.Warn(
			"Failed to parse minimum trivy version - skipping as cannot confirm if module will work with current version",
			log.Prefix("rego"),
			log.FilePath(module.Package.Location.File),
			log.Err(err),
		)
		return false
	}

	if tv.LessThan(mmsv) {
		log.Warn(
			"Module will be skipped as current version of Trivy is older than minimum trivy version required - please update Trivy to use this module",
			log.Prefix("rego"),
			log.FilePath(module.Package.Location.File),
			log.String("minimum_trivy_version", metadata.MinimumTrivyVersion),
		)
		return false
	}
	return true
}

// FrameworksFilter returns a filter that allows only modules
// associated with the specified frameworks.
func FrameworksFilter(frameworks []framework.Framework) RegoModuleFilter {
	return func(_ *ast.Module, metadata *StaticMetadata) bool {
		return metadata.matchAnyFramework(frameworks)
	}
}

// IncludeDeprecatedFilter returns a filter that allows deprecated modules
// if the include flag is true.
func IncludeDeprecatedFilter(include bool) RegoModuleFilter {
	return func(_ *ast.Module, metadata *StaticMetadata) bool {
		if metadata.Deprecated && !include {
			return false
		}
		return true
	}
}

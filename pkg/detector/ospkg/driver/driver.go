package driver

import (
	"context"

	"github.com/samber/lo"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Driver defines operations for OS package scan
type Driver interface {
	Detect(context.Context, string, *ftypes.Repository, []ftypes.Package) ([]types.DetectedVulnerability, error)
	IsSupportedVersion(context.Context, ftypes.OSType, string) bool
}

// Provider creates a specialized driver based on the environment
type Provider func(osFamily ftypes.OSType, pkgs []ftypes.Package) Driver

// PackageFilter is an optional interface a Driver can implement to narrow the package
// set before Detect with its own logic instead of the default third-party filtering.
type PackageFilter interface {
	FilterPackages(context.Context, []ftypes.Package) []ftypes.Package
}

// DropThirdPartyPackages removes packages installed from third-party repositories (e.g. EPEL, Docker).
// An OS vendor's advisories do not describe them, so matching by name reports fixes that do not apply.
//
// It must not be used by a driver whose own feed covers the packages it scans.
// There, third-party packages are exactly the ones the feed exists for.
func DropThirdPartyPackages(ctx context.Context, pkgs []ftypes.Package) []ftypes.Package {
	var skipped []string
	filtered := lo.Filter(pkgs, func(pkg ftypes.Package, _ int) bool {
		if pkg.Repository.Class == ftypes.RepositoryClassThirdParty {
			skipped = append(skipped, pkg.Name)
			return false
		}
		return true
	})
	if len(skipped) > 0 {
		log.DebugContext(ctx, "Skipping third-party packages", log.Any("packages", skipped))
	}
	return filtered
}

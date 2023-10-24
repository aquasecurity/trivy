package common

import (
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/purl"
	"github.com/aquasecurity/trivy/pkg/types"
)

// BuildPkgIdentifier builds a PkgIdentifier for the given package
// If there's no package reference, try to build a pURL from the package
func BuildPkgIdentifier(pkg ftypes.Package, t ftypes.TargetType, osName string) *types.PkgIdentifier {
	switch pkg.Ref {
	case "":
		metadata := types.Metadata{
			OS: &ftypes.OS{
				Family: t,
				Name:   osName,
			},
		}
		pkgURL, err := purl.NewPackageURL(t, metadata, pkg)
		if err != nil || pkgURL.Type == "" {
			return nil
		}

		return types.NewPkgIdentifier(pkgURL.String())
	default:
		return types.NewPkgIdentifier(pkg.Ref)
	}
}

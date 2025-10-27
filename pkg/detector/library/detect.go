package library

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/library/driver"
	"github.com/aquasecurity/trivy/pkg/detector/library/generic"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

func newDriver(libType ftypes.LangType, _ []ftypes.Package) (driver.Driver, bool) {
	//// Try providers first
	// for _, provider := range providers {
	//	if d := provider(osFamily, pkgs); d != nil {
	//		return d, nil
	//	}
	//}

	return generic.NewDriver(libType)
}

// Detect scans language-specific packages and returns vulnerabilities.
func Detect(ctx context.Context, libType ftypes.LangType, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	genericDriver, ok := newDriver(libType, pkgs)
	if !ok {
		return nil, nil
	}

	vulns, err := detect(ctx, genericDriver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", genericDriver.Type(), err)
	}

	return vulns, nil
}

func detect(ctx context.Context, driver driver.Driver, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	var vulnerabilities []types.DetectedVulnerability
	for _, pkg := range pkgs {
		if pkg.Version == "" {
			log.DebugContext(ctx, "Skipping vulnerability scan as no version is detected for the package",
				log.String("name", pkg.Name))
			continue
		}
		vulns, err := driver.Detect(ctx, pkg)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}

		for i := range vulns {
			vulns[i].Layer = pkg.Layer
			vulns[i].PkgPath = pkg.FilePath
			vulns[i].PkgIdentifier = pkg.Identifier
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

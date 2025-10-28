package library

import (
	"context"

	"github.com/aquasecurity/trivy/pkg/detector/library/rootio"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/library/driver"
	"github.com/aquasecurity/trivy/pkg/detector/library/generic"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// providers dynamically generate drivers based on package information
// and environment detection. They are tried before standard OS-specific drivers.
var providers = []driver.Provider{
	rootio.Provider,
}

func newDriver(libType ftypes.LangType, pkgs []ftypes.Package) (driver.Driver, bool) {
	// Try providers first
	for _, provider := range providers {
		if d := provider(libType, pkgs); d != nil {
			return d, true
		}
	}

	return generic.NewScanner(libType)
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

		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

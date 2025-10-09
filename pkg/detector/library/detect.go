package library

import (
	"context"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/detector/library/rootio"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// DriverProvider is a function that creates driver functions if applicable
type DriverProvider func(ftypes.LangType, []ftypes.Package) (typeFunc func() string, detectFunc func(string, string, string) ([]types.DetectedVulnerability, error))

// providers dynamically generate drivers based on package information
var providers = []DriverProvider{
	rootio.Provider,
}

// Detect scans language-specific packages and returns vulnerabilities.
func Detect(ctx context.Context, libType ftypes.LangType, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	driver := newDriver(libType, pkgs)
	if driver.Type() == "" {
		return nil, nil
	}

	vulns, err := detect(ctx, driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(ctx context.Context, driver Driver, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	var vulnerabilities []types.DetectedVulnerability
	for _, pkg := range pkgs {
		if pkg.Version == "" {
			log.DebugContext(ctx, "Skipping vulnerability scan as no version is detected for the package",
				log.String("name", pkg.Name))
			continue
		}
		vulns, err := driver.DetectVulnerabilities(pkg.ID, pkg.Name, pkg.Version)
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

func newDriver(libType ftypes.LangType, pkgs []ftypes.Package) Driver {
	// Try providers first
	for _, provider := range providers {
		if typeFunc, detectFunc := provider(libType, pkgs); typeFunc != nil && detectFunc != nil {
			return NewCustomDriver(typeFunc, detectFunc)
		}
	}

	// Fall back to standard driver
	driver, ok := NewDriver(libType)
	if !ok {
		return Driver{}
	}
	return driver
}

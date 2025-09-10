package library

import (
	"context"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Provider is a function that creates a Driver based on library type and packages
type Provider func(ftypes.LangType, []ftypes.Package) interface{}

// providers are dynamically generated drivers based on package information
var providers []Provider

// RegisterProvider registers a provider for dynamic driver creation
func RegisterProvider(p Provider) {
	providers = append(providers, p)
}

// Detect scans language-specific packages and returns vulnerabilities.
func Detect(ctx context.Context, libType ftypes.LangType, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	// Try providers first
	var driver Driver
	for _, provider := range providers {
		if d := provider(libType, pkgs); d != nil {
			// Convert the interface to a Driver
			if dynamicDriver, ok := d.(interface {
				Type() string
				DetectVulnerabilities(pkgID, pkgName, pkgVer string) ([]types.DetectedVulnerability, error)
			}); ok {
				driver = Driver{
					typeFunc:                  dynamicDriver.Type,
					detectVulnerabilitiesFunc: dynamicDriver.DetectVulnerabilities,
				}
				break
			}
		}
	}

	// Fall back to standard driver if no provider matched
	if driver.Type() == "" {
		var ok bool
		driver, ok = NewDriver(libType)
		if !ok {
			return nil, nil
		}
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

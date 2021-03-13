package library

import (
	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Detect scans and returns vulnerabilities of library
func Detect(libType string, pkgs []ftypes.LibraryInfo) ([]types.DetectedVulnerability, error) {
	driver, err := NewDriver(libType)
	if err != nil {
		return nil, xerrors.Errorf("failed to new driver: %w", err)
	}

	vulns, err := detect(driver, pkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to scan %s vulnerabilities: %w", driver.Type(), err)
	}

	return vulns, nil
}

func detect(driver Driver, libs []ftypes.LibraryInfo) ([]types.DetectedVulnerability, error) {
	var vulnerabilities []types.DetectedVulnerability
	for _, lib := range libs {
		vulns, err := driver.Detect(lib.Library.Name, lib.Library.Version)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect %s vulnerabilities: %w", driver.Type(), err)
		}

		for i := range vulns {
			vulns[i].Layer = lib.Layer
		}
		vulnerabilities = append(vulnerabilities, vulns...)
	}

	return vulnerabilities, nil
}

package library

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

type Driver interface {
	Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error)
	Type() string
}

type driver struct {
	pkgManager PackageManager
	advisories []advisory
}

type advisory interface {
	DetectVulnerabilities(string, *version.Version) ([]types.DetectedVulnerability, error)
}

func NewDriver(p PackageManager, advisories ...advisory) Driver {
	return &driver{pkgManager: p, advisories: advisories}
}

func (d *driver) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIdMap := make(map[string]struct{})
	for _, d := range d.advisories {
		vulns, err := d.DetectVulnerabilities(pkgName, pkgVer)
		if err != nil {
			return nil, xerrors.Errorf("failed to detect error: %w", err)
		}
		for _, vuln := range vulns {
			if _, ok := uniqVulnIdMap[vuln.VulnerabilityID]; ok {
				continue
			}
			uniqVulnIdMap[vuln.VulnerabilityID] = struct{}{}
			detectedVulnerabilities = append(detectedVulnerabilities, vuln)
		}
	}

	return detectedVulnerabilities, nil
}

func (d *driver) Type() string {
	return d.pkgManager.String()
}

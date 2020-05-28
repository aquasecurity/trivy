package library

import (
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

const (
	scannerType = "unknown"
)

type Scanner struct {
	drivers []driver
	pos     driver
}

func NewScanner(drivers ...driver) *Scanner {
	var pos driver
	if len(drivers) > 0 {
		pos = drivers[0]
	}
	return &Scanner{drivers: drivers, pos: pos}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	var detectedVulnerabilities []types.DetectedVulnerability
	uniqVulnIdMap := make(map[string]struct{})
	for _, d := range s.drivers {
		s.pos = d
		vulns, err := d.Detect(pkgName, pkgVer)
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

func (s *Scanner) Type() string {
	if s.pos == nil {
		return scannerType
	}
	return s.pos.Type()
}

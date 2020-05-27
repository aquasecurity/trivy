package library

import (
	"os"

	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

const (
	scannerType = "unknown"
)

type Scanner struct {
	drivers []Driver
	pos     Driver
}

func NewScanner(drivers ...Driver) *Scanner {
	var pos Driver
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

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	if s.pos == nil {
		return nil, xerrors.New("unsupport parse lockfile")
	}
	return s.pos.ParseLockfile(f)
}

func (s *Scanner) Type() string {
	if s.pos == nil {
		return scannerType
	}
	return s.pos.Type()
}

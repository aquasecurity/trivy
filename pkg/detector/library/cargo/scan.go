package cargo

import (
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/types"

	"github.com/aquasecurity/go-dep-parser/pkg/cargo"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	cargoSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/cargo"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

const (
	scannerType = "cargo"
)

type Scanner struct {
	vs cargoSrc.VulnSrc
}

func NewScanner() *Scanner {
	return &Scanner{
		vs: cargoSrc.NewVulnSrc(),
	}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get %s advisories: %w", s.Type(), err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          strings.TrimSpace(pkgName),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	libs, err := cargo.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid Cargo.lock format: %w", err)
	}
	return libs, nil
}

func (s *Scanner) Type() string {
	return scannerType
}

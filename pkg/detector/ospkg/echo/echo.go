package echo

import (
	"context"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	echoDb "github.com/aquasecurity/trivy-db/pkg/vulnsrc/echo"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"
)

type Scanner struct {
	vs echoDb.VulnSrc
}

func NewScanner() *Scanner {
	return &Scanner{
		vs: echoDb.NewVulnSrc(),
	}
}

func (s *Scanner) Detect(ctx context.Context, osName string, repo *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.Int("pkg_num", len(pkgs)))
	detectedVulns := []types.DetectedVulnerability{}
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get echo advisories: %w", err)
		}
		installedVersion, err := version.NewVersion(pkg.Version)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse installed version: %w", err)
		}
		for _, advisory := range advisories {
			vuln := types.DetectedVulnerability{
				PkgID:            pkg.ID,
				VulnerabilityID:  advisory.VulnerabilityID,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     advisory.FixedVersion,
				PkgName:          pkg.Name,
				PkgIdentifier:    pkg.Identifier,
				Status:           advisory.Status,
				Layer:            pkg.Layer,
				Custom:           advisory.Custom,
				DataSource:       advisory.DataSource,
			}

			if advisory.Severity != dbTypes.SeverityUnknown {
				vuln.Vulnerability = dbTypes.Vulnerability{
					Severity: advisory.Severity.String(),
				}
			}

			if advisory.FixedVersion != "" {
				fixedVersion, err := version.NewVersion(advisory.FixedVersion)
				if err != nil {
					return nil, xerrors.Errorf("failed to parse fixed version: %w", err)
				}
				if !installedVersion.LessThan(fixedVersion) {
					continue
				}
			}
			detectedVulns = append(detectedVulns, vuln)
		}
	}
	return detectedVulns, nil
}

func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return true
}

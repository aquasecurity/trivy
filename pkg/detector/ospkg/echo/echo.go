package echo

import (
	"context"

	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	echoDb "github.com/aquasecurity/trivy-db/pkg/vulnsrc/echo"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner struct {
	vs echoDb.VulnSrc
}

func NewScanner() *Scanner {
	return &Scanner{
		vs: echoDb.NewVulnSrc(),
	}
}

func (s *Scanner) Detect(ctx context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.Int("pkg_num", len(pkgs)))
	var detectedVulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(db.GetParams{
			PkgName: pkg.SrcName,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get echo advisories: %w", err)
		}
		formattedInstalledVersion := utils.FormatSrcVersion(pkg)
		installedVersion, err := version.NewVersion(formattedInstalledVersion)
		if err != nil {
			return nil, xerrors.Errorf("failed to parse installed version: %w", err)
		}
		for _, advisory := range advisories {
			vuln := types.DetectedVulnerability{
				PkgID:            pkg.ID,
				VulnerabilityID:  advisory.VulnerabilityID,
				InstalledVersion: formattedInstalledVersion,
				FixedVersion:     advisory.FixedVersion,
				PkgName:          pkg.Name,
				PkgIdentifier:    pkg.Identifier,
				Status:           advisory.Status,
				Layer:            pkg.Layer,
				Custom:           advisory.Custom,
				DataSource:       advisory.DataSource,
			}

			if advisory.Severity != dbTypes.SeverityUnknown {
				vuln.SeveritySource = vulnerability.Echo
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

// Echo is a rolling distro, meaning there are no versions, and therefor no need to check the version
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

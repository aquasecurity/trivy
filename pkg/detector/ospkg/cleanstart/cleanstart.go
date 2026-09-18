package cleanstart

import (
	"context"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/cleanstart"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the CleanStart scanner
type Scanner struct {
	vs cleanstart.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: cleanstart.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using CleanStart scanner
func (s *Scanner) Detect(ctx context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}
		advisories, err := s.vs.Get(db.GetParams{
			PkgName: srcName,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get CleanStart advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse the installed package version",
				log.String("version", installed), log.Err(err))
			continue
		}

		for _, adv := range advisories {
			if !s.isVulnerable(ctx, installedVersion, adv) {
				continue
			}
			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				FixedVersion:     adv.FixedVersion,
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			})
		}
	}
	return vulns, nil
}

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion version.Version, adv dbTypes.Advisory) bool {
	fixedVersion, err := version.NewVersion(adv.FixedVersion)
	if err != nil {
		log.DebugContext(ctx, "Failed to parse the fixed version",
			log.String("version", adv.FixedVersion), log.Err(err))
		return false
	}
	return installedVersion.LessThan(fixedVersion)
}

// IsSupportedVersion checks if the version is supported.
// CleanStart is a rolling release so all versions are always supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}
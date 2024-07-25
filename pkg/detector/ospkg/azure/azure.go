package azure

import (
	"context"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/azure"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the CBL-Mariner scanner
type Scanner struct {
	vs azure.VulnSrc
}

// NewScanner is the factory method for Scanner
func newScanner(distribution azure.Distribution) *Scanner {
	return &Scanner{
		vs: azure.NewVulnSrc(distribution),
	}
}

func NewAzureScanner() *Scanner {
	return newScanner(azure.Azure)
}

func NewMarinerScanner() *Scanner {
	return newScanner(azure.Mariner)
}

// Detect vulnerabilities in package using CBL-Mariner scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	// e.g. 1.0.20210127
	osVer = osver.Minor(osVer)

	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		// Azure Linux OVAL contains source package names only.
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Azure Linux advisories: %w", err)
		}

		sourceVersion := version.NewVersion(utils.FormatSrcVersion(pkg))

		for _, adv := range advisories {
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				PkgIdentifier:    pkg.Identifier,
				Layer:            pkg.Layer,
				DataSource:       adv.DataSource,
			}

			// Unpatched vulnerabilities
			if adv.FixedVersion == "" {
				vulns = append(vulns, vuln)
				continue
			}

			// Patched vulnerabilities
			fixedVersion := version.NewVersion(adv.FixedVersion)
			if sourceVersion.LessThan(fixedVersion) {
				vuln.FixedVersion = fixedVersion.String()
				vulns = append(vulns, vuln)
			}
		}
	}

	return vulns, nil
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	// EOL is not in public at the moment.
	return true
}

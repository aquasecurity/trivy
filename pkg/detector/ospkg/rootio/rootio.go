package rootio

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/rootio"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Root.io scanner
type Scanner struct {
	comparer version.Comparer
	vs       rootio.VulnSrc
	logger   *log.Logger
}

// NewScanner is the factory method for Scanner
func NewScanner(baseOS ftypes.OSType) *Scanner {
	var comparer version.Comparer
	var vs rootio.VulnSrc

	switch baseOS {
	case ftypes.Debian:
		comparer = version.NewDEBComparer()
		vs = rootio.NewVulnSrc(vulnerability.Debian)
	case ftypes.Ubuntu:
		comparer = version.NewDEBComparer()
		vs = rootio.NewVulnSrc(vulnerability.Ubuntu)
	case ftypes.Alpine:
		comparer = version.NewAPKComparer()
		vs = rootio.NewVulnSrc(vulnerability.Alpine)
	default:
		// Should never happen as it's validated in the provider
		comparer = version.NewDEBComparer()
		vs = rootio.NewVulnSrc(vulnerability.Debian)
	}

	return &Scanner{
		comparer: comparer,
		vs:       vs,
		logger:   log.WithPrefix("rootio"),
	}
}

// Detect vulnerabilities in package using Root.io scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer), log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}

		advisories, err := s.vs.Get(osVer, srcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Root.io advisories: %w", err)
		}

		for _, adv := range advisories {
			if !s.isVulnerable(ctx, utils.FormatSrcVersion(pkg), adv) {
				continue
			}
			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     strings.Join(adv.PatchedVersions, ", "),
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			})
		}
	}
	return vulns, nil
}

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	// Handle unfixed vulnerabilities
	if len(adv.VulnerableVersions) == 0 {
		// If no vulnerable versions are specified, it means the package is always vulnerable
		return true
	}

	// For fixed vulnerabilities, check if installed version satisfies the constraint
	return s.checkConstraints(ctx, installedVersion, adv.VulnerableVersions)
}

func (s *Scanner) checkConstraints(ctx context.Context, installedVersion string, constraintsStr []string) bool {
	if installedVersion == "" {
		return false
	}

	for _, constraintStr := range constraintsStr {
		constraints, err := version.NewConstraints(constraintStr, s.comparer)
		if err != nil {
			s.logger.DebugContext(ctx, "Failed to parse constraints",
				log.String("constraints", constraintStr), log.Err(err))
			return false
		}

		if satisfied, err := constraints.Check(installedVersion); err != nil {
			s.logger.DebugContext(ctx, "Failed to check version constraints",
				log.String("version", installedVersion),
				log.String("constraints", constraintStr), log.Err(err))
			return false
		} else if satisfied {
			return true
		}
	}
	return false
}

// IsSupportedVersion checks if the version is supported.
// Root.io creates fixes for EOL distributions, so we assume all versions are supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

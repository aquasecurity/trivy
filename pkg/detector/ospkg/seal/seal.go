package seal

import (
	"context"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/seal"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/alpine"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/azure"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/debian"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/driver"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/redhat"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/ubuntu"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner implements the Seal scanner
type Scanner struct {
	comparer       version.Comparer
	scanner        driver.Driver
	vsg            seal.VulnSrcGetter
	versionTrimmer func(string) string
	logger         *log.Logger
}

// NewScanner is the factory method for Scanner
func NewScanner(baseOS ftypes.OSType) *Scanner {
	var scanner driver.Driver
	var comparer version.Comparer
	var vsg seal.VulnSrcGetter
	var versionTrimmer func(string) string

	switch baseOS {
	case ftypes.Alpine:
		scanner = alpine.NewScanner()
		comparer = version.NewAPKComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.Alpine)
		versionTrimmer = version.Minor
	case ftypes.CBLMariner:
		scanner = azure.NewMarinerScanner()
		comparer = version.NewRPMComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.CBLMariner)
		versionTrimmer = version.Minor
	case ftypes.CentOS:
		scanner = redhat.NewScanner()
		comparer = version.NewRPMComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.CentOS)
		versionTrimmer = version.Major
	case ftypes.Debian:
		scanner = debian.NewScanner()
		comparer = version.NewDEBComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.Debian)
		versionTrimmer = version.Major
	case ftypes.RedHat:
		scanner = redhat.NewScanner()
		comparer = version.NewRPMComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.RedHat)
		versionTrimmer = version.Major
	case ftypes.Ubuntu:
		scanner = ubuntu.NewScanner()
		comparer = version.NewDEBComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.Ubuntu)
		versionTrimmer = version.Minor
	default:
		// Should never happen as it's validated in the provider
		comparer = version.NewDEBComparer()
		vsg = seal.NewVulnSrcGetter(vulnerability.Debian)
		versionTrimmer = version.Major
	}

	return &Scanner{
		scanner:        scanner,
		comparer:       comparer,
		vsg:            vsg,
		versionTrimmer: versionTrimmer,
		logger:         log.WithPrefix("seal"),
	}
}

// Detect vulnerabilities in package using Seal scanner
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer), log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	var baseOSPkgs ftypes.Packages
	for _, pkg := range pkgs {
		// Keep non-Seal packages to scan them with the base OS scanner later
		if !sealPkg(pkg) {
			baseOSPkgs = append(baseOSPkgs, pkg)
			continue
		}

		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}

		advisories, err := s.vsg.Get(db.GetParams{
			// Trim patch/minor part of osVer.
			// e.g. "12.0.1" -> "12" (Debian), "24.04.1" -> "24.04" (Ubuntu), "3.17.2" -> "3.17" (Alpine)
			Release: s.versionTrimmer(osVer),
			PkgName: srcName,
		})
		if err != nil {
			return nil, xerrors.Errorf("failed to get Seal advisories: %w", err)
		}

		for _, adv := range advisories {
			if !s.isVulnerable(ctx, utils.FormatSrcVersion(pkg), adv) {
				continue
			}
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     strings.Join(adv.PatchedVersions, ", "),
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}

			if adv.Severity != dbTypes.SeverityUnknown {
				// Package-specific severity
				vuln.SeveritySource = adv.DataSource.BaseID
				vuln.Vulnerability = dbTypes.Vulnerability{
					Severity: adv.Severity.String(),
				}
			}

			vulns = append(vulns, vuln)
		}
	}

	// Detect vulns for baseOS packages.
	baseOSVulns, err := s.scanner.Detect(ctx, osVer, nil, baseOSPkgs)
	if err != nil {
		return nil, xerrors.Errorf("failed to detect vulnerabilities with base OS scanner: %w", err)
	}

	return append(baseOSVulns, vulns...), nil
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
// Seal creates fixes for EOL distributions, so we assume all versions are supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

func sealPkg(pkg ftypes.Package) bool {
	// Seal packages start with "seal-"
	return strings.HasPrefix(strings.ToLower(pkg.Name), "seal-") || strings.HasPrefix(strings.ToLower(pkg.SrcName), "seal-")
}

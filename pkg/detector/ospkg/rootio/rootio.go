package rootio

import (
	"context"

	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)


// Scanner implements the Root.io scanner
type Scanner struct {
	baseOS   ftypes.OSType
	comparer version.Comparer
	vs       VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner(baseOS ftypes.OSType) Scanner {
	return Scanner{
		baseOS:   baseOS,
		comparer: selectComparer(baseOS),
		vs:       newMockVulnSrc(baseOS),
	}
}

func selectComparer(baseOS ftypes.OSType) version.Comparer {
	switch baseOS {
	case ftypes.Debian, ftypes.Ubuntu:
		return version.NewDEBComparer()
	case ftypes.Alpine:
		return version.NewAPKComparer()
	default:
		return version.NewDEBComparer()
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

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory) bool {
	// Handle unfixed vulnerabilities
	if adv.FixedVersion == "" {
		// Check if the package is affected by parsing the AffectedVersion constraints
		if adv.AffectedVersion != "" {
			return s.checkConstraints(ctx, installedVersion, adv.AffectedVersion)
		}
		// If no constraints, assume vulnerable
		return true
	}

	// For fixed vulnerabilities, check if installed version satisfies the constraint
	return s.checkConstraints(ctx, installedVersion, adv.FixedVersion)
}

func (s *Scanner) checkConstraints(ctx context.Context, installedVersion, constraintStr string) bool {
	if constraintStr == "" || installedVersion == "" {
		return false
	}

	// Use DEB comparer as default - Root.io constraints are generic
	comparer := version.NewDEBComparer()
	constraints, err := version.NewConstraints(constraintStr, comparer)
	if err != nil {
		log.DebugContext(ctx, "Failed to parse constraints",
			log.String("constraints", constraintStr), log.Err(err))
		return false
	}

	satisfied, err := constraints.Check(installedVersion)
	if err != nil {
		log.DebugContext(ctx, "Failed to check version constraints",
			log.String("version", installedVersion),
			log.String("constraints", constraintStr), log.Err(err))
		return false
	}

	return satisfied
}

// IsSupportedVersion checks if the version is supported.
// Root.io provides generic vulnerability data, so all versions are supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}
package dhi

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// Scanner detects vulnerabilities in Alpine- and Debian-based DHI packages.
type Scanner struct {
	dbc db.Operation
}

// NewScanner returns a DHI package scanner backed by the Trivy vulnerability database.
func NewScanner() *Scanner {
	return &Scanner{dbc: db.Config{}}
}

// Detect finds release-scoped DHI advisories and applies the package manager's version semantics.
//
// DHI advisories are ingested from OSV, so trivy-db stores their ranges as
// VulnerableVersions constraints (e.g. "<9.11-r1") and PatchedVersions, never
// as a single FixedVersion. An advisory without any VulnerableVersions is
// unfixed and applies to every installed version.
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting DHI vulnerabilities...", log.String("os_version", osVer), log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		pkgName := pkg.SrcName
		if pkgName == "" {
			pkgName = pkg.Name
		}

		lineage, comparer := packageLineage(pkg)
		if lineage == "" {
			log.DebugContext(ctx, "Skipping DHI package with unknown package type", log.String("package", pkg.Name))
			continue
		}
		advisories, err := s.dbc.GetAdvisories(fmt.Sprintf("dhi %s %s", lineage, osVer), pkgName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get DHI advisories: %w", err)
		}

		for _, adv := range advisories {
			if len(adv.Arches) > 0 && !slices.Contains(adv.Arches, pkg.Arch) {
				continue
			}
			if !isVulnerable(ctx, utils.FormatSrcVersion(pkg), adv, comparer) {
				continue
			}

			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				VendorIDs:        adv.VendorIDs,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     strings.Join(adv.PatchedVersions, ", "),
				PkgIdentifier:    pkg.Identifier,
				Status:           adv.Status,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			})
		}
	}
	return vulns, nil
}

// isVulnerable reports whether installedVersion satisfies any of the advisory's
// vulnerable version constraints under the package manager's version semantics.
func isVulnerable(ctx context.Context, installedVersion string, adv dbTypes.Advisory, comparer version.Comparer) bool {
	// No constraints means the advisory is unfixed: every version is affected.
	if len(adv.VulnerableVersions) == 0 {
		return true
	}
	if installedVersion == "" {
		return false
	}

	for _, constraintStr := range adv.VulnerableVersions {
		constraints, err := version.NewConstraints(constraintStr, comparer)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse DHI version constraints",
				log.String("constraints", constraintStr), log.Err(err))
			continue
		}
		satisfied, err := constraints.Check(installedVersion)
		if err != nil {
			log.DebugContext(ctx, "Failed to check DHI version constraints",
				log.String("version", installedVersion), log.String("constraints", constraintStr), log.Err(err))
			continue
		}
		if satisfied {
			return true
		}
	}
	return false
}

func packageType(pkg ftypes.Package) string {
	if pkg.Identifier.PURL != nil {
		switch pkg.Identifier.PURL.Type {
		case "apk":
			return "apk"
		case "deb":
			return "deb"
		}
	}
	switch pkg.AnalyzedBy {
	case "apk":
		return "apk"
	case "dpkg":
		return "deb"
	default:
		return ""
	}
}

// packageLineage returns the DHI advisory lineage and the version comparer
// that matches the package's native package manager.
func packageLineage(pkg ftypes.Package) (string, version.Comparer) {
	switch packageType(pkg) {
	case "apk":
		return "alpine", version.NewAPKComparer()
	case "deb":
		return "debian", version.NewDEBComparer()
	default:
		return "", nil
	}
}

// IsSupportedVersion returns true because support is determined by release-scoped DHI advisories.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

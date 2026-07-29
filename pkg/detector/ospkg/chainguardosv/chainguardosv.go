// Package chainguardosv detects vulnerabilities in the APK packages of a
// Chainguard or Wolfi image using the advisories from Chainguard's OSV v3 feed.
//
// The feed replaced the deprecated secdb feed for both distros. Unlike secdb it
// also publishes advisories Chainguard has not resolved yet, which are reported
// as vulnerabilities with no fixed version. `--ignore-unfixed` leaves them out,
// and `--ignore-status` leaves out individual resolution statuses.
//
// Feed documentation:
// https://github.com/chainguard-dev/vulnerability-scanner-support/blob/main/docs/osv_v3_feed.md
package chainguardosv

import (
	"cmp"
	"context"
	"slices"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

// archAny is the APK architecture of a package that is not built for one
// particular architecture, so every advisory applies to it.
const archAny = "noarch"

// Scanner detects vulnerabilities in APK packages built by Chainguard.
type Scanner struct {
	vs     db.Getter
	distro string
}

// NewScanner returns a Scanner reading from vs. The distro name is only used in
// log lines and error messages.
func NewScanner(vs db.Getter, distro string) *Scanner {
	return &Scanner{
		vs:     vs,
		distro: distro,
	}
}

// Detect scans the given packages for known vulnerabilities.
func (s *Scanner) Detect(ctx context.Context, _ string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("distro", s.distro),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.advisories(pkg)
		if err != nil {
			return nil, xerrors.Errorf("failed to get %s advisories: %w", s.distro, err)
		}
		if len(advisories) == 0 {
			continue
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse the installed package version",
				log.String("version", installed), log.Err(err))
			continue
		}

		for _, adv := range dedupe(advisories, pkg.Arch) {
			if !s.isVulnerable(ctx, installedVersion, adv) {
				continue
			}
			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				VendorIDs:        adv.VendorIDs,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: installed,
				FixedVersion:     adv.FixedVersion,
				Status:           adv.Status,
				Layer:            pkg.Layer,
				PkgIdentifier:    pkg.Identifier,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			})
		}
	}
	return vulns, nil
}

// advisories collects the advisories that apply to a package.
//
// The feed files an advisory against the APK package the vulnerable component
// was found in, which is the subpackage when a subpackage is what ships the
// component, and against the origin package otherwise. Since a subpackage is
// built from its origin and carries its origin's version numbers, both sets
// apply and both have to be looked up: an origin such as kubeflow-katib and a
// subpackage such as katib-suggestion-skopt-enas each carry advisories the
// other does not.
func (s *Scanner) advisories(pkg ftypes.Package) ([]dbTypes.Advisory, error) {
	names := []string{pkg.Name}
	if pkg.SrcName != "" && pkg.SrcName != pkg.Name {
		names = append(names, pkg.SrcName)
	}

	var advisories []dbTypes.Advisory
	for _, name := range names {
		found, err := s.vs.Get(db.GetParams{
			PkgName: name,
			Arch:    pkg.Arch,
		})
		if err != nil {
			return nil, err
		}
		advisories = append(advisories, found...)
	}
	return advisories, nil
}

func (s *Scanner) isVulnerable(ctx context.Context, installedVersion version.Version, adv dbTypes.Advisory) bool {
	// Chainguard has not resolved the vulnerability, so every version of the
	// package is affected and there is nothing to compare against.
	if adv.FixedVersion == "" {
		return true
	}

	fixedVersion, err := version.NewVersion(adv.FixedVersion)
	if err != nil {
		log.DebugContext(ctx, "Failed to parse the fixed version",
			log.String("version", adv.FixedVersion), log.Err(err))
		return false
	}
	return installedVersion.LessThan(fixedVersion)
}

// dedupe reduces the advisories for each vulnerability to a single one.
//
// A package carries one advisory per architecture, and looking a package up
// under both its own name and its origin name brings back more than one
// advisory for the same vulnerability. The advisories for the package's own
// architecture are the accurate ones, so they win when the feed has any. The
// feed does not always cover both architectures though - around one in eleven
// package/vulnerability pairs appears for a single architecture only - so when
// nothing matches, the advisories for the other architecture are used rather
// than dropping the vulnerability. Chainguard builds every architecture of a
// package from the same source, so an advisory recorded for one of them is
// evidence about the other.
//
// Among the remaining candidates an unresolved advisory wins, because it means
// Chainguard has not established that any version of the package is safe.
// Otherwise the highest fixed version wins, since a lower one would report the
// vulnerability as fixed while another component or architecture is still
// waiting for it.
func dedupe(advisories []dbTypes.Advisory, pkgArch string) []dbTypes.Advisory {
	byVulnID := make(map[string][]dbTypes.Advisory)
	for _, adv := range advisories {
		byVulnID[adv.VulnerabilityID] = append(byVulnID[adv.VulnerabilityID], adv)
	}

	deduped := make([]dbTypes.Advisory, 0, len(byVulnID))
	for _, candidates := range byVulnID {
		if matching := matchArch(candidates, pkgArch); len(matching) > 0 {
			candidates = matching
		}

		best := candidates[0]
		for _, candidate := range candidates[1:] {
			if preferred(best, candidate) {
				best = candidate
			}
		}
		deduped = append(deduped, best)
	}

	slices.SortFunc(deduped, func(a, b dbTypes.Advisory) int {
		return cmp.Compare(a.VulnerabilityID, b.VulnerabilityID)
	})
	return deduped
}

// matchArch returns the advisories that apply to pkgArch. Everything applies to
// a package with no architecture or an architecture-independent package, and an
// advisory with no architecture applies to every package.
func matchArch(advisories []dbTypes.Advisory, pkgArch string) []dbTypes.Advisory {
	if pkgArch == "" || pkgArch == archAny {
		return advisories
	}

	var matching []dbTypes.Advisory
	for _, adv := range advisories {
		if len(adv.Arches) == 0 || slices.Contains(adv.Arches, pkgArch) {
			matching = append(matching, adv)
		}
	}
	return matching
}

// preferred reports whether candidate should replace current.
func preferred(current, candidate dbTypes.Advisory) bool {
	if candidate.FixedVersion == "" {
		return current.FixedVersion != ""
	}
	if current.FixedVersion == "" {
		return false
	}

	currentFixed, err := version.NewVersion(current.FixedVersion)
	if err != nil {
		return true
	}
	candidateFixed, err := version.NewVersion(candidate.FixedVersion)
	if err != nil {
		return false
	}
	return currentFixed.LessThan(candidateFixed)
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	// Neither Chainguard nor Wolfi has distro versions, so there is no input
	// that yields an unsupported version. The VERSION_ID in /etc/os-release is
	// the version of the baselayout package, not of the distro.
	return true
}

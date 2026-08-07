package dhi

import (
	"context"
	"fmt"
	"slices"

	apkVersion "github.com/knqyf263/go-apk-version"
	debVersion "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/db"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting DHI vulnerabilities...", log.String("os_version", osVer), log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		pkgName := pkg.SrcName
		if pkgName == "" {
			pkgName = pkg.Name
		}

		lineage := packageLineage(pkg)
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
			if !isVulnerable(ctx, pkg, adv) {
				continue
			}

			vulns = append(vulns, types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				VendorIDs:        adv.VendorIDs,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     adv.FixedVersion,
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

func isVulnerable(ctx context.Context, pkg ftypes.Package, adv dbTypes.Advisory) bool {
	if adv.FixedVersion == "" {
		return true
	}

	installed := utils.FormatSrcVersion(pkg)
	switch packageType(pkg) {
	case "apk":
		installedVersion, err := apkVersion.NewVersion(installed)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse installed APK version", log.String("version", installed), log.Err(err))
			return false
		}
		fixedVersion, err := apkVersion.NewVersion(adv.FixedVersion)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse fixed APK version", log.String("version", adv.FixedVersion), log.Err(err))
			return false
		}
		return installedVersion.LessThan(fixedVersion)
	case "deb":
		installedVersion, err := debVersion.NewVersion(installed)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse installed Debian version", log.String("version", installed), log.Err(err))
			return false
		}
		fixedVersion, err := debVersion.NewVersion(adv.FixedVersion)
		if err != nil {
			log.DebugContext(ctx, "Failed to parse fixed Debian version", log.String("version", adv.FixedVersion), log.Err(err))
			return false
		}
		return installedVersion.LessThan(fixedVersion)
	default:
		log.DebugContext(ctx, "Skipping DHI package with unknown package type", log.String("package", pkg.Name))
		return false
	}
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

func packageLineage(pkg ftypes.Package) string {
	switch packageType(pkg) {
	case "apk":
		return "alpine"
	case "deb":
		return "debian"
	default:
		return ""
	}
}

// IsSupportedVersion returns true because support is determined by release-scoped DHI advisories.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

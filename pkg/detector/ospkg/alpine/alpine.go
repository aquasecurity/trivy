package alpine

import (
	"context"
	"strings"
	"time"

	version "github.com/knqyf263/go-apk-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alpine"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"2.0":  time.Date(2012, 4, 1, 23, 59, 59, 0, time.UTC),
		"2.1":  time.Date(2012, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.2":  time.Date(2013, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.3":  time.Date(2013, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.4":  time.Date(2014, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.5":  time.Date(2014, 11, 1, 23, 59, 59, 0, time.UTC),
		"2.6":  time.Date(2015, 5, 1, 23, 59, 59, 0, time.UTC),
		"2.7":  time.Date(2015, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.0":  time.Date(2016, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.1":  time.Date(2016, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.2":  time.Date(2017, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.3":  time.Date(2017, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.4":  time.Date(2018, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.5":  time.Date(2018, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.6":  time.Date(2019, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.7":  time.Date(2019, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.8":  time.Date(2020, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.9":  time.Date(2020, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.10": time.Date(2021, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.11": time.Date(2021, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.12": time.Date(2022, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.13": time.Date(2022, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.14": time.Date(2023, 5, 1, 23, 59, 59, 0, time.UTC),
		"3.15": time.Date(2023, 11, 1, 23, 59, 59, 0, time.UTC),
		"3.16": time.Date(2024, 5, 23, 23, 59, 59, 0, time.UTC),
		"3.17": time.Date(2024, 11, 22, 23, 59, 59, 0, time.UTC),
		"3.18": time.Date(2025, 5, 9, 23, 59, 59, 0, time.UTC),
		"3.19": time.Date(2025, 11, 1, 23, 59, 59, 0, time.UTC),
		"edge": time.Date(9999, 1, 1, 0, 0, 0, 0, time.UTC),
	}
)

// Scanner implements the Alpine scanner
type Scanner struct {
	vs alpine.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: alpine.NewVulnSrc(),
	}
}

// Detect vulnerabilities in package using Alpine scanner
func (s *Scanner) Detect(osVer string, repo *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Alpine vulnerabilities...")
	osVer = osver.Minor(osVer)
	repoRelease := s.repoRelease(repo)

	log.Logger.Debugf("alpine: os version: %s", osVer)
	log.Logger.Debugf("alpine: package repository: %s", repoRelease)
	log.Logger.Debugf("alpine: the number of packages: %d", len(pkgs))

	stream := osVer
	if repoRelease != "" && osVer != repoRelease {
		// Prefer the repository release. Use OS version only when the repository is not detected.
		stream = repoRelease
		if repoRelease != "edge" { // TODO: we should detect the current edge version.
			log.Logger.Warnf("Mixing Alpine versions is unsupported, OS: '%s', repository: '%s'", osVer, repoRelease)
		}
	}

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		srcName := pkg.SrcName
		if srcName == "" {
			srcName = pkg.Name
		}
		advisories, err := s.vs.Get(stream, srcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get alpine advisories: %w", err)
		}

		sourceVersion, err := version.NewVersion(utils.FormatSrcVersion(pkg))
		if err != nil {
			log.Logger.Debugf("failed to parse Alpine Linux installed package version: %s", err)
			continue
		}

		for _, adv := range advisories {
			if !s.isVulnerable(sourceVersion, adv) {
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

func (s *Scanner) isVulnerable(installedVersion version.Version, adv dbTypes.Advisory) bool {
	// This logic is for unfixed vulnerabilities, but Trivy DB doesn't have advisories for unfixed vulnerabilities for now
	// because Alpine just provides potentially vulnerable packages. It will cause a lot of false positives.
	// This is for Aqua commercial products.
	if adv.AffectedVersion != "" {
		// AffectedVersion means which version introduced this vulnerability.
		affectedVersion, err := version.NewVersion(adv.AffectedVersion)
		if err != nil {
			log.Logger.Debugf("failed to parse Alpine Linux affected package version: %s", err)
			return false
		}
		if affectedVersion.GreaterThan(installedVersion) {
			return false
		}
	}

	// This logic is also for unfixed vulnerabilities.
	if adv.FixedVersion == "" {
		// It means the unfixed vulnerability
		return true
	}

	// Compare versions for fixed vulnerabilities
	fixedVersion, err := version.NewVersion(adv.FixedVersion)
	if err != nil {
		log.Logger.Debugf("failed to parse Alpine Linux fixed version: %s", err)
		return false
	}

	// It means the fixed vulnerability
	return installedVersion.LessThan(fixedVersion)
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osver.Minor(osVer))
}

func (s *Scanner) repoRelease(repo *ftypes.Repository) string {
	if repo == nil {
		return ""
	}
	release := repo.Release
	if strings.Count(release, ".") > 1 {
		release = release[:strings.LastIndex(release, ".")]
	}
	return release
}

package ubuntu

import (
	"context"
	"strings"
	"time"

	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/ubuntu"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		"4.10":      time.Date(2006, 4, 30, 23, 59, 59, 0, time.UTC),
		"5.04":      time.Date(2006, 10, 31, 23, 59, 59, 0, time.UTC),
		"5.10":      time.Date(2007, 4, 13, 23, 59, 59, 0, time.UTC),
		"6.06":      time.Date(2011, 6, 1, 23, 59, 59, 0, time.UTC),
		"6.10":      time.Date(2008, 4, 25, 23, 59, 59, 0, time.UTC),
		"7.04":      time.Date(2008, 10, 19, 23, 59, 59, 0, time.UTC),
		"7.10":      time.Date(2009, 4, 18, 23, 59, 59, 0, time.UTC),
		"8.04":      time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC),
		"8.10":      time.Date(2010, 4, 30, 23, 59, 59, 0, time.UTC),
		"9.04":      time.Date(2010, 10, 23, 23, 59, 59, 0, time.UTC),
		"9.10":      time.Date(2011, 4, 29, 23, 59, 59, 0, time.UTC),
		"10.04":     time.Date(2015, 4, 29, 23, 59, 59, 0, time.UTC),
		"10.10":     time.Date(2012, 4, 10, 23, 59, 59, 0, time.UTC),
		"11.04":     time.Date(2012, 10, 28, 23, 59, 59, 0, time.UTC),
		"11.10":     time.Date(2013, 5, 9, 23, 59, 59, 0, time.UTC),
		"12.04":     time.Date(2019, 4, 26, 23, 59, 59, 0, time.UTC),
		"12.04-ESM": time.Date(2019, 4, 28, 23, 59, 59, 0, time.UTC),
		"12.10":     time.Date(2014, 5, 16, 23, 59, 59, 0, time.UTC),
		"13.04":     time.Date(2014, 1, 27, 23, 59, 59, 0, time.UTC),
		"13.10":     time.Date(2014, 7, 17, 23, 59, 59, 0, time.UTC),
		"14.04":     time.Date(2022, 4, 25, 23, 59, 59, 0, time.UTC),
		"14.04-ESM": time.Date(2024, 4, 25, 23, 59, 59, 0, time.UTC),
		"14.10":     time.Date(2015, 7, 23, 23, 59, 59, 0, time.UTC),
		"15.04":     time.Date(2016, 1, 23, 23, 59, 59, 0, time.UTC),
		"15.10":     time.Date(2016, 7, 22, 23, 59, 59, 0, time.UTC),
		"16.04":     time.Date(2021, 4, 21, 23, 59, 59, 0, time.UTC),
		"16.04-ESM": time.Date(2026, 4, 29, 23, 59, 59, 0, time.UTC),
		"16.10":     time.Date(2017, 7, 20, 23, 59, 59, 0, time.UTC),
		"17.04":     time.Date(2018, 1, 13, 23, 59, 59, 0, time.UTC),
		"17.10":     time.Date(2018, 7, 19, 23, 59, 59, 0, time.UTC),
		"18.04":     time.Date(2023, 5, 31, 23, 59, 59, 0, time.UTC),
		"18.04-ESM": time.Date(2028, 3, 31, 23, 59, 59, 0, time.UTC),
		"18.10":     time.Date(2019, 7, 18, 23, 59, 59, 0, time.UTC),
		"19.04":     time.Date(2020, 1, 18, 23, 59, 59, 0, time.UTC),
		"19.10":     time.Date(2020, 7, 17, 23, 59, 59, 0, time.UTC),
		"20.04":     time.Date(2025, 4, 23, 23, 59, 59, 0, time.UTC),
		"20.10":     time.Date(2021, 7, 22, 23, 59, 59, 0, time.UTC),
		"21.04":     time.Date(2022, 1, 20, 23, 59, 59, 0, time.UTC),
		"21.10":     time.Date(2022, 7, 14, 23, 59, 59, 0, time.UTC),
		"22.04":     time.Date(2027, 4, 23, 23, 59, 59, 0, time.UTC),
		"22.10":     time.Date(2023, 7, 20, 23, 59, 59, 0, time.UTC),
		"23.04":     time.Date(2024, 1, 20, 23, 59, 59, 0, time.UTC),
		"23.10":     time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"24.04":     time.Date(2034, 3, 31, 23, 59, 59, 0, time.UTC),
		"24.10":     time.Date(2025, 7, 9, 23, 59, 59, 0, time.UTC),
	}
)

// Scanner implements the Ubuntu scanner
type Scanner struct {
	vs ubuntu.VulnSrc
}

// NewScanner is the factory method for Scanner
func NewScanner() *Scanner {
	return &Scanner{
		vs: ubuntu.NewVulnSrc(),
	}
}

// Detect scans and returns the vulnerabilities
func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting vulnerabilities...", log.String("os_version", osVer),
		log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		osVer = s.versionFromEolDates(osVer)
		advisories, err := s.vs.Get(osVer, pkg.SrcName)
		if err != nil {
			return nil, xerrors.Errorf("failed to get Ubuntu advisories: %w", err)
		}

		sourceVersion, err := version.NewVersion(utils.FormatSrcVersion(pkg))
		if err != nil {
			log.DebugContext(ctx, "Failed to parse the installed package version", log.Err(err))
			continue
		}

		for _, adv := range advisories {
			vuln := types.DetectedVulnerability{
				VulnerabilityID:  adv.VulnerabilityID,
				PkgID:            pkg.ID,
				PkgName:          pkg.Name,
				InstalledVersion: utils.FormatVersion(pkg),
				FixedVersion:     adv.FixedVersion,
				PkgIdentifier:    pkg.Identifier,
				Layer:            pkg.Layer,
				Custom:           adv.Custom,
				DataSource:       adv.DataSource,
			}

			if adv.FixedVersion == "" {
				vulns = append(vulns, vuln)
				continue
			}

			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.DebugContext(ctx, "Failed to parse the fixed version",
					log.String("version", adv.FixedVersion), log.Err(err))
				continue
			}

			if sourceVersion.LessThan(fixedVersion) {
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks is OSFamily can be scanned using Ubuntu scanner
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osVer)
}

// versionFromEolDates checks if actual (not ESM) version is not outdated
func (s *Scanner) versionFromEolDates(osVer string) string {
	if _, ok := eolDates[osVer]; ok {
		return osVer
	}

	// if base version (not ESM) is still actual
	// we need to use this version
	// e.g. Ubuntu doesn't have vulnerabilities for `18.04-ESM`, because `18.04` is not outdated
	// then we need to get vulnerabilities for `18.04`
	// if `18.04` is outdated - we need to use `18.04-ESM` (we will return error until we add `18.04-ESM` to eolDates)
	ver := strings.TrimRight(osVer, "-ESM")
	if eol, ok := eolDates[ver]; ok && time.Now().Before(eol) { // TODO: time.Now() should be replaced with clock.Now()
		return ver
	}
	return osVer
}

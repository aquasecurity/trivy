package amazon

import (
	"strings"
	"time"

	version "github.com/knqyf263/go-deb-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/amazon"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	eolDates = map[string]time.Time{
		// https://aws.amazon.com/jp/blogs/aws/update-on-amazon-linux-ami-end-of-life/
		"1": time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
		// https://aws.amazon.com/amazon-linux-2/faqs/?nc1=h_ls
		"2": time.Date(2025, 6, 30, 23, 59, 59, 0, time.UTC),
		// Amazon Linux 2022 was renamed to 2023. AL2022 is not currently supported.
		"2023": time.Date(2028, 3, 15, 23, 59, 59, 0, time.UTC),
	}
)

type options struct {
	clock clock.Clock
}

type option func(*options)

func WithClock(c clock.Clock) option {
	return func(opts *options) {
		opts.clock = c
	}
}

// Scanner to scan amazon vulnerabilities
type Scanner struct {
	ac amazon.VulnSrc
	options
}

// NewScanner is the factory method to return Amazon scanner
func NewScanner(opts ...option) *Scanner {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}
	return &Scanner{
		ac:      amazon.NewVulnSrc(),
		options: *o,
	}
}

// Detect scans the packages using amazon scanner
func (s *Scanner) Detect(osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting Amazon Linux vulnerabilities...")

	osVer = strings.Fields(osVer)[0]
	if osVer != "2" && osVer != "2022" && osVer != "2023" {
		osVer = "1"
	}
	log.Logger.Debugf("amazon: os version: %s", osVer)
	log.Logger.Debugf("amazon: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.ac.Get(osVer, pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get amazon advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		if installed == "" {
			continue
		}

		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Amazon Linux installed package version: %s", err)
			continue
		}

		for _, adv := range advisories {
			fixedVersion, err := version.NewVersion(adv.FixedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Amazon Linux package version: %s", err)
				continue
			}

			if installedVersion.LessThan(fixedVersion) {
				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgID:            pkg.ID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
					PkgRef:           pkg.Ref,
					Layer:            pkg.Layer,
					Custom:           adv.Custom,
					DataSource:       adv.DataSource,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion checks if the version is supported.
func (s *Scanner) IsSupportedVersion(osFamily ftypes.OSType, osVer string) bool {
	osVer = strings.Fields(osVer)[0]
	if osVer != "2" && osVer != "2022" && osVer != "2023" {
		osVer = "1"
	}

	return osver.Supported(s.clock, eolDates, osFamily, osVer)
}

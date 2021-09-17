package arch

import (
	version "github.com/MaineK00n/go-pacman-version"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"

	ftypes "github.com/aquasecurity/fanal/types"
	archlinux "github.com/aquasecurity/trivy-db/pkg/vulnsrc/arch-linux"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

type options struct {
	clock clock.Clock
}

type option func(*options)

func WithClock(clock clock.Clock) option {
	return func(opts *options) {
		opts.clock = clock
	}
}

// Scanner implements the ArchLinux scanner
type Scanner struct {
	vs archlinux.VulnSrc
	*options
}

// NewScanner is the factory method for Scanner
func NewScanner(opts ...option) *Scanner {
	o := &options{
		clock: clock.RealClock{},
	}

	for _, opt := range opts {
		opt(o)
	}
	return &Scanner{
		vs:      archlinux.NewVulnSrc(),
		options: o,
	}
}

// Detect vulnerabilities in package using ArchLinux scanner
func (s *Scanner) Detect(_ string, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.Logger.Info("Detecting ArchLinux vulnerabilities...")
	log.Logger.Debugf("arch: the number of packages: %d", len(pkgs))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		advisories, err := s.vs.Get(pkg.Name)
		if err != nil {
			return nil, xerrors.Errorf("failed to get arch advisories: %w", err)
		}

		installed := utils.FormatVersion(pkg)
		installedVersion, err := version.NewVersion(installed)
		if err != nil {
			log.Logger.Debugf("failed to parse Arch Linux installed package version: %s", err)
			continue
		}

		for _, adv := range advisories {
			affectedVersion, err := version.NewVersion(adv.AffectedVersion)
			if err != nil {
				log.Logger.Debugf("failed to parse Arch Linux affected version: %s", err)
				continue
			}
			if installedVersion.GreaterThan(affectedVersion) || installedVersion.Equal(affectedVersion) {
				if adv.FixedVersion != "" {
					fixedVersion, err := version.NewVersion(adv.FixedVersion)
					if err != nil {
						log.Logger.Debugf("failed to parse Arch Linux fixed version: %s", err)
						continue
					}
					if !installedVersion.LessThan(fixedVersion) {
						continue
					}
				}

				vuln := types.DetectedVulnerability{
					VulnerabilityID:  adv.VulnerabilityID,
					PkgName:          pkg.Name,
					InstalledVersion: installed,
					FixedVersion:     adv.FixedVersion,
					Layer:            pkg.Layer,
				}
				vulns = append(vulns, vuln)
			}
		}
	}
	return vulns, nil
}

// IsSupportedVersion always returns true, since Arch Linux is rolling release
func (s *Scanner) IsSupportedVersion(osFamily, _ string) bool {
	return true
}

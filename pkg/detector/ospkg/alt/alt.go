package alt

import (
	"context"
	"sort"
	"strings"
	"time"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ustrings "github.com/aquasecurity/trivy-db/pkg/utils/strings"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/alt"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	osver "github.com/aquasecurity/trivy/pkg/detector/ospkg/version"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
	"github.com/cheggaaa/pb/v3"
	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"
	"golang.org/x/xerrors"
	"k8s.io/utils/clock"
)

var (
	eolDates = map[string]time.Time{
		"p9":    time.Date(2023, 12, 31, 23, 59, 59, 0, time.UTC),
		"p10":   time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"p11":   time.Date(2027, 12, 31, 23, 59, 59, 0, time.UTC),
		"c9f2":  time.Date(2026, 8, 10, 23, 59, 59, 0, time.UTC),
		"c10f1": time.Date(2024, 6, 30, 23, 59, 59, 0, time.UTC),
		"c10f2": time.Date(2028, 8, 10, 23, 59, 59, 0, time.UTC),
	}
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

// Scanner implements the ALT scanner with ALT` vuln source
type Scanner struct {
	vs alt.VulnSrc
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
		vs:      alt.NewVulnSrc(),
		options: o,
	}
}

// IsSupportedVersion checks the OSFamily can be scanned using ALT scanner
func (s *Scanner) IsSupportedVersion(ctx context.Context, osFamily ftypes.OSType, osVer string) bool {
	return osver.Supported(ctx, eolDates, osFamily, osVer)
}

func (s *Scanner) Detect(ctx context.Context, cpe string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting ALT vulnerabilities...")
	log.DebugContext(ctx, "ALT: os version: ", log.String("cpe", fromCPE(cpe)))
	log.DebugContext(ctx, "ALT: the number of packages: ", log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	p := pb.New(len(pkgs))
	p.Start()
	for _, pkg := range pkgs {
		detectedVulns, err := s.detect(cpe, pkg)
		if err != nil {
			return nil, xerrors.Errorf("ALT vulnerability detection error: %w", err)
		}
		vulns = append(vulns, detectedVulns...)
		p.Increment()
	}
	p.Finish()
	return vulns, nil
}

func (s *Scanner) detect(cpe string, pkg ftypes.Package) ([]types.DetectedVulnerability, error) {
	advisories, err := s.vs.Get(pkg.Name, cpe)
	if err != nil {
		return nil, xerrors.Errorf("failed to get ALT advisories: %w", err)
	}

	installed := utils.FormatVersion(pkg)
	installedVersion := version.NewVersion(installed)

	uniqVulns := map[string]types.DetectedVulnerability{}
	for _, adv := range advisories {
		if len(adv.Arches) != 0 && pkg.Arch != "noarch" {
			if !slices.Contains(adv.Arches, pkg.Arch) {
				continue
			}
		}
		vulnID := adv.VulnerabilityID
		vuln := types.DetectedVulnerability{
			VulnerabilityID:  vulnID,
			PkgID:            pkg.ID,
			PkgName:          pkg.Name,
			InstalledVersion: utils.FormatVersion(pkg),
			PkgIdentifier:    pkg.Identifier,
			Layer:            pkg.Layer,
			SeveritySource:   vulnerability.ALT,
			Vulnerability: dbTypes.Vulnerability{
				Severity: adv.Severity.String(),
			},
			Custom: adv.Custom,
		}

		if adv.FixedVersion == "" {
			if _, ok := uniqVulns[vulnID]; !ok {
				uniqVulns[vulnID] = vuln
			}
			continue
		}

		fixedVersion := version.NewVersion(adv.FixedVersion)
		if installedVersion.LessThan(fixedVersion) {
			vuln.VendorIDs = adv.VendorIDs
			vuln.FixedVersion = fixedVersion.String()

			if v, ok := uniqVulns[vulnID]; ok {
				v.VendorIDs = ustrings.Unique(append(v.VendorIDs, vuln.VendorIDs...))

				if version.NewVersion(v.FixedVersion).LessThan(fixedVersion) {
					v.FixedVersion = vuln.FixedVersion
				}
				uniqVulns[vulnID] = v
			} else {
				uniqVulns[vulnID] = vuln
			}
		}
	}

	vulns := maps.Values(uniqVulns)
	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].VulnerabilityID < vulns[j].VulnerabilityID
	})

	return vulns, nil
}

func fromCPE(cpe string) string {
	if strings.Contains(cpe, "sp") && strings.Contains(cpe, "9") {
		return "c9f2"
	}
	if strings.Contains(cpe, "sp") && strings.Contains(cpe, "10") {
		return "c10f1"
	}
	if strings.Contains(cpe, "sp") && strings.Contains(cpe, "10") && strings.Contains(cpe, "2") {
		return "c10f2"
	}
	if !strings.Contains(cpe, "sp") && strings.Contains(cpe, "11") {
		return "p11"
	}
	if !strings.Contains(cpe, "sp") && strings.Contains(cpe, "10") {
		return "p10"
	}
	if !strings.Contains(cpe, "sp") && strings.Contains(cpe, "9") {
		return "p9"
	}
	return "undefined"
}

package hummingbird

import (
	"context"
	"fmt"
	"slices"
	"sort"

	version "github.com/knqyf263/go-rpm-version"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	redhat "github.com/aquasecurity/trivy-db/pkg/vulnsrc/redhat-oval"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/scan/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var defaultContentSets = []string{
	"public-hummingbird-x86_64-rpms",
	"public-hummingbird-aarch64-rpms",
	"public-hummingbird-source-rpms",
}

type Scanner struct {
	vs redhat.VulnSrc
}

func NewScanner() *Scanner {
	return &Scanner{
		vs: redhat.NewVulnSrc(),
	}
}

func (s *Scanner) Detect(ctx context.Context, osVer string, _ *ftypes.Repository, pkgs []ftypes.Package) ([]types.DetectedVulnerability, error) {
	log.InfoContext(ctx, "Detecting Hummingbird vulnerabilities...",
		log.String("os_version", osVer), log.Int("pkg_num", len(pkgs)))

	var vulns []types.DetectedVulnerability
	for _, pkg := range pkgs {
		detectedVulns, err := s.detect(pkg)
		if err != nil {
			return nil, xerrors.Errorf("hummingbird vulnerability detection error: %w", err)
		}
		vulns = append(vulns, detectedVulns...)
	}
	return vulns, nil
}

func (s *Scanner) detect(pkg ftypes.Package) ([]types.DetectedVulnerability, error) {
	var contentSets []string
	var nvr string
	if pkg.BuildInfo == nil {
		contentSets = defaultContentSets
	} else {
		contentSets = pkg.BuildInfo.ContentSets
		nvr = fmt.Sprintf("%s-%s", pkg.BuildInfo.Nvr, pkg.BuildInfo.Arch)
	}

	advisories, err := s.vs.Get(pkg.Name, contentSets, []string{nvr})
	if err != nil {
		return nil, xerrors.Errorf("failed to get Hummingbird advisories: %w", err)
	}

	// Fall back to source RPM name if no advisories found by binary name.
	// The VEX feed may reference source RPM names instead of binary RPM names.
	if len(advisories) == 0 && pkg.SrcName != "" && pkg.SrcName != pkg.Name {
		advisories, err = s.vs.Get(pkg.SrcName, contentSets, []string{nvr})
		if err != nil {
			return nil, xerrors.Errorf("failed to get Hummingbird advisories by source name: %w", err)
		}
	}

	uniqAdvisories := make(map[string]dbTypes.Advisory)
	for _, adv := range advisories {
		if len(adv.Arches) != 0 && pkg.Arch != "noarch" {
			if !slices.Contains(adv.Arches, pkg.Arch) {
				continue
			}
		}

		if a, ok := uniqAdvisories[adv.VulnerabilityID]; ok {
			if version.NewVersion(a.FixedVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
				uniqAdvisories[adv.VulnerabilityID] = adv
			}
		} else {
			uniqAdvisories[adv.VulnerabilityID] = adv
		}
	}

	var vulns []types.DetectedVulnerability
	for _, adv := range uniqAdvisories {
		vuln := types.DetectedVulnerability{
			VulnerabilityID:  adv.VulnerabilityID,
			VendorIDs:        adv.VendorIDs,
			PkgID:            pkg.ID,
			PkgName:          pkg.Name,
			InstalledVersion: utils.FormatVersion(pkg),
			FixedVersion:     version.NewVersion(adv.FixedVersion).String(),
			PkgIdentifier:    pkg.Identifier,
			Status:           adv.Status,
			Layer:            pkg.Layer,
			SeveritySource:   vulnerability.RedHat,
			Vulnerability: dbTypes.Vulnerability{
				Severity: adv.Severity.String(),
			},
			Custom: adv.Custom,
		}

		if adv.FixedVersion == "" || version.NewVersion(vuln.InstalledVersion).LessThan(version.NewVersion(adv.FixedVersion)) {
			vulns = append(vulns, vuln)
		}
	}

	sort.Slice(vulns, func(i, j int) bool {
		return vulns[i].VulnerabilityID < vulns[j].VulnerabilityID
	})
	return vulns, nil
}

// Hummingbird uses date-based versioning and has no EOL dates.
func (s *Scanner) IsSupportedVersion(_ context.Context, _ ftypes.OSType, _ string) bool {
	return true
}

package bundler

import (
	"strings"

	"github.com/Masterminds/semver/v3"
	"golang.org/x/xerrors"

	bundlerSrc "github.com/aquasecurity/trivy-db/pkg/vulnsrc/bundler"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	platformReplacer = strings.NewReplacer(
		"-java", "+java",
		"-mswin32", "+msin32",
		"-mswin64", "+mswin64",
		"-universal-mingw32", "+universal-mingw32",
		"-x64-mingw32", "+x64-mingw32",
		"-x86_64-mingw32", "+x86_64-mingw32",
		"-mingw32", "+mingw32",
	)
)

type VulnSrc interface {
	Get(pkgName string) ([]bundlerSrc.Advisory, error)
}

type Advisory struct {
	vs VulnSrc
}

func massageLockFileVersion(version string) string {
	// Move the platform into "metadata" semver section.
	// This is because otherwise we end up placing it in the "pre-release" section
	// of the semver value, and this breaks our version comparisons in the scanner.
	return platformReplacer.Replace(version)
}

func NewAdvisory() *Advisory {
	return &Advisory{
		vs: bundlerSrc.NewVulnSrc(),
	}
}

func (a *Advisory) DetectVulnerabilities(pkgName string, pkgVer *semver.Version) ([]types.DetectedVulnerability, error) {
	advisories, err := a.vs.Get(pkgName)
	if err != nil {
		return nil, xerrors.Errorf("failed to get bundler advisories: %w", err)
	}

	var vulns []types.DetectedVulnerability
	for _, advisory := range advisories {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}
		if utils.MatchVersions(pkgVer, advisory.UnaffectedVersions) {
			continue
		}

		vuln := types.DetectedVulnerability{
			VulnerabilityID:  advisory.VulnerabilityID,
			PkgName:          strings.TrimSpace(pkgName),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

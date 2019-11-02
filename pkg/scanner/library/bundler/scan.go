package bundler

import (
	"fmt"
	"os"
	"strings"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

	"github.com/aquasecurity/go-dep-parser/pkg/bundler"
	ptypes "github.com/aquasecurity/go-dep-parser/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanner/utils"
	"github.com/knqyf263/go-version"
	"golang.org/x/xerrors"
)

const (
	scannerType = "bundler"
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

type Scanner struct {
	db AdvisoryDB
}

func massageLockFileVersion(version string) string {
	// Move the platform into "metadata" semver section.
	// This is because otherwise we end up placing it in the "pre-release" section
	// of the semver value, and this breaks our version comparisons in the scanner.
	return platformReplacer.Replace(version)
}

func NewScanner() *Scanner {
	return &Scanner{}
}

func (s *Scanner) Detect(pkgName string, pkgVer *version.Version) ([]vulnerability.DetectedVulnerability, error) {
	var vulns []vulnerability.DetectedVulnerability
	for _, advisory := range s.db[pkgName] {
		if utils.MatchVersions(pkgVer, advisory.PatchedVersions) {
			continue
		}
		if utils.MatchVersions(pkgVer, advisory.UnaffectedVersions) {
			continue
		}

		var vulnerabilityID string
		if advisory.Cve != "" {
			vulnerabilityID = fmt.Sprintf("CVE-%s", advisory.Cve)
		} else if advisory.Osvdb != "" {
			vulnerabilityID = fmt.Sprintf("OSVDB-%s", advisory.Osvdb)
		}

		vuln := vulnerability.DetectedVulnerability{
			VulnerabilityID:  vulnerabilityID,
			PkgName:          strings.TrimSpace(advisory.Gem),
			Title:            strings.TrimSpace(advisory.Title),
			InstalledVersion: pkgVer.String(),
			FixedVersion:     strings.Join(advisory.PatchedVersions, ", "),
		}
		vulns = append(vulns, vuln)
	}
	return vulns, nil
}

func (s *Scanner) ParseLockfile(f *os.File) ([]ptypes.Library, error) {
	libs, err := bundler.Parse(f)
	if err != nil {
		return nil, xerrors.Errorf("invalid Gemfile.lock format: %w", err)
	}

	for _, lib := range libs {
		lib.Version = massageLockFileVersion(lib.Version)
	}

	return libs, nil
}

func (s *Scanner) Type() string {
	return scannerType
}

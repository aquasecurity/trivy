package flag

import (
	"fmt"
	"strings"

	"github.com/samber/lo"
	"github.com/spf13/cobra"
	"golang.org/x/exp/slices"

	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

var (
	SkipDirsFlag = Flag{
		Name:       "skip-dirs",
		ConfigName: "scan.skip-dirs",
		Value:      "",
		Usage:      "specify the directories where the traversal is skipped",
	}
	SkipFilesFlag = Flag{
		Name:       "skip-files",
		ConfigName: "scan.skip-files",
		Value:      "",
		Usage:      "specify the file paths to skip traversal",
	}
	OfflineScanFlag = Flag{
		Name:       "offline-scan",
		ConfigName: "scan.offline",
		Value:      false,
		Usage:      "do not issue API requests to identify dependencies",
	}
	SecurityChecksFlag = Flag{
		Name:       "security-checks",
		ConfigName: "scan.security-checks",
		Value:      fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret),
		Usage:      "comma-separated list of what security issues to detect (vuln,config,secret)",
	}
	VulnTypeFlag = Flag{
		Name:       "vuln-type",
		ConfigName: "vulnerability.type",
		Value:      strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","),
		Usage:      "comma-separated list of vulnerability types (os,library)",
	}
	SecretConfigFlag = Flag{
		Name:       "secret-config",
		ConfigName: "secret.config",
		Value:      "trivy-secret.yaml",
		Usage:      "specify a path to config file for secret scanning",
	}
)

type ScanFlagGroup struct {
	SkipDirs       *Flag
	SkipFiles      *Flag
	OfflineScan    *Flag
	SecurityChecks *Flag

	VulnType     *Flag
	SecretConfig *Flag
}

type ScanOptions struct {
	Target         string
	SkipDirs       []string
	SkipFiles      []string
	OfflineScan    bool
	SecurityChecks []string

	// Vulnerabilities
	VulnType []string

	// Secrets
	SecretConfigPath string
}

func NewScanFlagGroup() *ScanFlagGroup {
	return &ScanFlagGroup{
		SkipDirs:       lo.ToPtr(SkipDirsFlag),
		SkipFiles:      lo.ToPtr(SkipFilesFlag),
		OfflineScan:    lo.ToPtr(OfflineScanFlag),
		SecurityChecks: lo.ToPtr(SecurityChecksFlag),
		VulnType:       lo.ToPtr(VulnTypeFlag),
		SecretConfig:   lo.ToPtr(SecretConfigFlag),
	}
}

func (f *ScanFlagGroup) flags() []*Flag {
	return []*Flag{f.SkipDirs, f.SkipFiles, f.OfflineScan, f.SecurityChecks, f.VulnType, f.SecretConfig}
}

func (f *ScanFlagGroup) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *ScanFlagGroup) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *ScanFlagGroup) ToOptions(args []string) ScanOptions {
	var target string
	if len(args) == 1 {
		target = args[0]
	}

	return ScanOptions{
		Target:           target,
		SkipDirs:         getStringSlice(f.SkipDirs),
		SkipFiles:        getStringSlice(f.SkipFiles),
		OfflineScan:      getBool(f.OfflineScan),
		VulnType:         parseVulnType(getStringSlice(f.VulnType)),
		SecurityChecks:   parseSecurityCheck(getStringSlice(f.SecurityChecks)),
		SecretConfigPath: getString(f.SecretConfig),
	}
}

func parseVulnType(vulnType []string) []string {
	switch {
	case len(vulnType) == 0: // no types
		return nil
	case len(vulnType) == 1 && strings.Contains(vulnType[0], ","): // get checks from flag
		vulnType = strings.Split(vulnType[0], ",")
	}

	var vulnTypes []string
	for _, v := range vulnType {
		if !slices.Contains(types.VulnTypes, v) {
			log.Logger.Warnf("unknown vulnerability type: %s", v)
			continue
		}
		vulnTypes = append(vulnTypes, v)
	}
	return vulnTypes
}

func parseSecurityCheck(securityCheck []string) []string {
	switch {
	case len(securityCheck) == 0: // no checks
		return nil
	case len(securityCheck) == 1 && strings.Contains(securityCheck[0], ","): // get checks from flag
		securityCheck = strings.Split(securityCheck[0], ",")
	}

	var securityChecks []string
	for _, v := range securityCheck {
		if !slices.Contains(types.SecurityChecks, v) {
			log.Logger.Warnf("unknown security check: %s", v)
			continue
		}
		securityChecks = append(securityChecks, v)
	}
	return securityChecks
}

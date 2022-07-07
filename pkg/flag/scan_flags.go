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
	VulnTypeFlag = Flag{
		Name:       "vuln-type",
		ConfigName: "scan.vulnerability.type",
		Value:      strings.Join([]string{types.VulnTypeOS, types.VulnTypeLibrary}, ","),
		Usage:      "comma-separated list of vulnerability types (os,library)",
	}
	SecurityChecksFlag = Flag{
		Name:       "security-checks",
		ConfigName: "scan.security-checks",
		Value:      fmt.Sprintf("%s,%s", types.SecurityCheckVulnerability, types.SecurityCheckSecret),
		Usage:      "comma-separated list of vulnerability types (os,library)",
	}
)

type ScanFlags struct {
	SkipDirs       *Flag
	SkipFiles      *Flag
	OfflineScan    *Flag
	VulnType       *Flag
	SecurityChecks *Flag
}

type ScanOptions struct {
	Target         string
	SkipDirs       []string
	SkipFiles      []string
	OfflineScan    bool
	VulnType       []string
	SecurityChecks []string
}

func NewScanFlags() *ScanFlags {
	return &ScanFlags{
		SkipDirs:       lo.ToPtr(SkipDirsFlag),
		SkipFiles:      lo.ToPtr(SkipFilesFlag),
		OfflineScan:    lo.ToPtr(OfflineScanFlag),
		VulnType:       lo.ToPtr(VulnTypeFlag),
		SecurityChecks: lo.ToPtr(SecurityChecksFlag),
	}
}

func (f *ScanFlags) flags() []*Flag {
	return []*Flag{f.SkipDirs, f.SkipFiles, f.OfflineScan, f.VulnType, f.SecurityChecks}
}

func (f *ScanFlags) Bind(cmd *cobra.Command) error {
	for _, flag := range f.flags() {
		if err := bind(cmd, flag); err != nil {
			return err
		}
	}
	return nil
}

func (f *ScanFlags) AddFlags(cmd *cobra.Command) {
	for _, flag := range f.flags() {
		addFlag(cmd, flag)
	}
}

func (f *ScanFlags) ToOptions(args []string) ScanOptions {
	var target string
	if len(args) == 1 {
		target = args[0]
	}

	return ScanOptions{
		Target:         target,
		SkipDirs:       get[[]string](f.SkipDirs),
		SkipFiles:      get[[]string](f.SkipFiles),
		OfflineScan:    get[bool](f.OfflineScan),
		VulnType:       parseVulnType(get[string](f.VulnType)),
		SecurityChecks: parseSecurityCheck(get[string](f.SecurityChecks)),
	}
}

func parseVulnType(vulnType string) []string {
	if vulnType == "" {
		return nil
	}

	var vulnTypes []string
	for _, v := range strings.Split(vulnType, ",") {
		if !slices.Contains(types.VulnTypes, v) {
			log.Logger.Warnf("unknown vulnerability type: %s", v)
			continue
		}
		vulnTypes = append(vulnTypes, v)
	}
	return vulnTypes
}

func parseSecurityCheck(securityCheck string) []string {
	if securityCheck == "" {
		return nil
	}

	var securityChecks []string
	for _, v := range strings.Split(securityCheck, ",") {
		if !slices.Contains(types.SecurityChecks, v) {
			log.Logger.Warnf("unknown security check: %s", v)
			continue
		}
		securityChecks = append(securityChecks, v)
	}
	return securityChecks
}

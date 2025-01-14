package table

import (
	"github.com/aquasecurity/table"
	"github.com/aquasecurity/trivy/pkg/types"
)

type Scanner interface {
	Header() string
	Alignment() table.Alignment

	// Count returns the number of findings, but -1 if the scanner is not applicable
	Count(result types.Result) int
}

func NewScanner(scanner types.Scanner) Scanner {
	switch scanner {
	case types.VulnerabilityScanner:
		return VulnerabilityScanner{}
	case types.MisconfigScanner:
		return MisconfigScanner{}
	case types.SecretScanner:
		return SecretScanner{}
	case types.LicenseScanner:
		return LicenseScanner{}
	}
	return nil
}

type scannerAlignment struct{}

func (s scannerAlignment) Alignment() table.Alignment {
	return table.AlignCenter
}

type VulnerabilityScanner struct{ scannerAlignment }

func (s VulnerabilityScanner) Header() string {
	return "Vulnerabilities"
}

func (s VulnerabilityScanner) Count(result types.Result) int {
	if result.Class == types.ClassOSPkg || result.Class == types.ClassLangPkg {
		return len(result.Vulnerabilities)
	}
	return -1
}

type MisconfigScanner struct{ scannerAlignment }

func (s MisconfigScanner) Header() string {
	return "Misconfigurations"
}

func (s MisconfigScanner) Count(result types.Result) int {
	if result.Class == types.ClassConfig {
		return len(result.Misconfigurations)
	}
	return -1
}

type SecretScanner struct{ scannerAlignment }

func (s SecretScanner) Header() string {
	return "Secrets"
}

func (s SecretScanner) Count(result types.Result) int {
	if result.Class == types.ClassSecret {
		return len(result.Secrets)
	}
	return -1
}

type LicenseScanner struct{ scannerAlignment }

func (s LicenseScanner) Header() string {
	return "Licenses"
}

func (s LicenseScanner) Count(result types.Result) int {
	if result.Class == types.ClassLicense {
		return len(result.Licenses)
	}
	return -1
}

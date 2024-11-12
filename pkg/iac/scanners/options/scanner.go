package options

import (
	"github.com/aquasecurity/trivy/pkg/iac/framework"
)

type ConfigurableScanner interface {
	SetFrameworks(frameworks []framework.Framework)
	SetIncludeDeprecatedChecks(bool)
}

func ScannerWithIncludeDeprecatedChecks(enabled bool) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetIncludeDeprecatedChecks(enabled)
	}
}

type ScannerOption func(s ConfigurableScanner)

func ScannerWithFrameworks(frameworks ...framework.Framework) ScannerOption {
	return func(s ConfigurableScanner) {
		s.SetFrameworks(frameworks)
	}
}

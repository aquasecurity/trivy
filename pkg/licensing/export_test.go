package licensing

import "github.com/aquasecurity/trivy/pkg/licensing/expression"

// Bridge to expose licensing internals to tests in the licensing_test package.

// StandardizeKeyAndSuffix exports standardizeKeyAndSuffix for testing.
func StandardizeKeyAndSuffix(name string) expression.SimpleExpr {
	return standardizeKeyAndSuffix(name)
}

// NormalizeLicense exports normalizeLicense for testing.
func NormalizeLicense(name string) string {
	return normalizeLicense(name)
}

// Mapping exports mapping for testing.
func Mapping() map[string]expression.SimpleExpr {
	return mapping
}

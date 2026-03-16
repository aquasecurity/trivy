package licensing

import "github.com/aquasecurity/trivy/pkg/licensing/expression"

// Bridge to expose licensing internals to tests in the licensing_test package.

// StandardizeKeyAndSuffix exports standardizeKeyAndSuffix for testing.
var StandardizeKeyAndSuffix = standardizeKeyAndSuffix

// NormalizeLicense exports normalizeLicense for testing.
var NormalizeLicense = normalizeLicense

// Mapping exports mapping for testing.
func Mapping() map[string]expression.SimpleExpr {
	return mapping
}

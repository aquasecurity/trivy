package types

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type DetectedLicense struct {
	// Severity is the consistent parameter indicating how severe the issue is
	Severity string

	// Category holds the license category such as "forbidden"
	Category types.LicenseCategory

	// PkgName holds a package name of the license.
	// It will be empty if FilePath is filled.
	PkgName string

	// PkgName holds a file path of the license.
	// It will be empty if PkgName is filled.
	FilePath string // for file license

	// Name holds a detected license name
	Name string

	// Confidence is level of the match. The confidence level is between 0.0 and 1.0, with 1.0 indicating an
	// exact match and 0.0 indicating a complete mismatch
	Confidence float64

	// Link is a SPDX link of the license
	Link string
}

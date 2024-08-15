package types

import (
	"github.com/aquasecurity/trivy/pkg/fanal/types"
)

type DetectedLicense struct {
	// Severity is the consistent parameter indicating how severe the issue is
	Severity string `json:",omitempty"`

	// Category holds the license category such as "forbidden"
	Category types.LicenseCategory `json:",omitempty"`

	// PkgName holds a package name which used the license.
	// It will be empty if FilePath is filled.
	PkgName string `json:",omitempty"`

	// PkgVersion holds the package version which used the license
	// It will be empty if FilePath is filled
	PkgVersion string `json:",omitempty"`

	PkgEpoch int `json:",omitempty"`

	// Release of the Package
	PkgRelease string `json:",omitempty"`

	// Type of the Package it belongs to
	PkgType types.TargetType `json:",omitempty"`

	// Pkg Class indicates Os Pkg / Lang Pkg
	PkgClass ResultClass `json:",omitempty"`

	// Target name of the package
	PkgTarget string `json:",omitempty"`

	// Filepath where the package was found
	PkgFilePath string `json:",omitempty"`

	// Is Package direct or indirect
	IsPkgIndirect bool `json:",omitempty"`

	// package ID correlates to the unique packageID as in types.Package struct
	PkgID string `json:",omitempty"`

	// For loose licenses, file path indicates where license was found
	// It will be empty if PkgName is filled
	FilePath string `json:",omitempty"`

	// Name holds a detected license name
	Name string

	// Type of the detected license
	Type types.LicenseType

	// true if license is a declared license, else it's a concluded license
	IsDeclared bool

	// true if license is a SPDX classified license, false otherwise
	IsSPDXClassified bool

	// Checksum of the license text found in license scanning
	LicenseTextChecksum string `json:",omitempty"`

	// Copyright text found within the license text
	CopyrightText string `json:",omitempty"`

	// Confidence is level of the match. The confidence level is between 0.0 and 1.0, with 1.0 indicating an
	// exact match and 0.0 indicating a complete mismatch
	Confidence float64 `json:"-"`

	// Link is a SPDX link of the license
	Link string `json:",omitempty"`
}

func (DetectedLicense) findingType() FindingType { return FindingTypeLicense }

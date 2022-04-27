// Package spdx contains the struct definition for an SPDX Document
// and its constituent parts.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
package spdx

// Document2_1 is an SPDX Document for version 2.1 of the spec.
// See https://spdx.org/sites/cpstandard/files/pages/files/spdxversion2.1.pdf
type Document2_1 struct {
	CreationInfo    *CreationInfo2_1
	Packages        map[ElementID]*Package2_1
	UnpackagedFiles map[ElementID]*File2_1
	OtherLicenses   []*OtherLicense2_1
	Relationships   []*Relationship2_1
	Annotations     []*Annotation2_1

	// DEPRECATED in version 2.0 of spec
	Reviews []*Review2_1
}

// Document2_2 is an SPDX Document for version 2.2 of the spec.
// See https://spdx.github.io/spdx-spec/v2-draft/ (DRAFT)
type Document2_2 struct {
	CreationInfo    *CreationInfo2_2
	Packages        map[ElementID]*Package2_2
	UnpackagedFiles map[ElementID]*File2_2
	OtherLicenses   []*OtherLicense2_2
	Relationships   []*Relationship2_2
	Annotations     []*Annotation2_2

	// DEPRECATED in version 2.0 of spec
	Reviews []*Review2_2
}

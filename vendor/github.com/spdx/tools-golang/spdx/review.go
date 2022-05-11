// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package spdx

// Review2_1 is a Review section of an SPDX Document for version 2.1 of the spec.
// DEPRECATED in version 2.0 of spec; retained here for compatibility.
type Review2_1 struct {

	// DEPRECATED in version 2.0 of spec
	// 9.1: Reviewer
	// Cardinality: optional, one
	Reviewer string
	// including AnnotatorType: one of "Person", "Organization" or "Tool"
	ReviewerType string

	// DEPRECATED in version 2.0 of spec
	// 9.2: Review Date: YYYY-MM-DDThh:mm:ssZ
	// Cardinality: conditional (mandatory, one) if there is a Reviewer
	ReviewDate string

	// DEPRECATED in version 2.0 of spec
	// 9.3: Review Comment
	// Cardinality: optional, one
	ReviewComment string
}

// Review2_2 is a Review section of an SPDX Document for version 2.2 of the spec.
// DEPRECATED in version 2.0 of spec; retained here for compatibility.
type Review2_2 struct {

	// DEPRECATED in version 2.0 of spec
	// 9.1: Reviewer
	// Cardinality: optional, one
	Reviewer string
	// including AnnotatorType: one of "Person", "Organization" or "Tool"
	ReviewerType string

	// DEPRECATED in version 2.0 of spec
	// 9.2: Review Date: YYYY-MM-DDThh:mm:ssZ
	// Cardinality: conditional (mandatory, one) if there is a Reviewer
	ReviewDate string

	// DEPRECATED in version 2.0 of spec
	// 9.3: Review Comment
	// Cardinality: optional, one
	ReviewComment string
}

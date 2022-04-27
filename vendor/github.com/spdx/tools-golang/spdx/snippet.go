// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package spdx

// Snippet2_1 is a Snippet section of an SPDX Document for version 2.1 of the spec.
type Snippet2_1 struct {

	// 5.1: Snippet SPDX Identifier: "SPDXRef-[idstring]"
	// Cardinality: mandatory, one
	SnippetSPDXIdentifier ElementID

	// 5.2: Snippet from File SPDX Identifier
	// Cardinality: mandatory, one
	SnippetFromFileSPDXIdentifier DocElementID

	// 5.3: Snippet Byte Range: [start byte]:[end byte]
	// Cardinality: mandatory, one
	SnippetByteRangeStart int
	SnippetByteRangeEnd   int

	// 5.4: Snippet Line Range: [start line]:[end line]
	// Cardinality: optional, one
	SnippetLineRangeStart int
	SnippetLineRangeEnd   int

	// 5.5: Snippet Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	SnippetLicenseConcluded string

	// 5.6: License Information in Snippet: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: optional, one or many
	LicenseInfoInSnippet []string

	// 5.7: Snippet Comments on License
	// Cardinality: optional, one
	SnippetLicenseComments string

	// 5.8: Snippet Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	SnippetCopyrightText string

	// 5.9: Snippet Comment
	// Cardinality: optional, one
	SnippetComment string

	// 5.10: Snippet Name
	// Cardinality: optional, one
	SnippetName string
}

// Snippet2_2 is a Snippet section of an SPDX Document for version 2.2 of the spec.
type Snippet2_2 struct {

	// 5.1: Snippet SPDX Identifier: "SPDXRef-[idstring]"
	// Cardinality: mandatory, one
	SnippetSPDXIdentifier ElementID

	// 5.2: Snippet from File SPDX Identifier
	// Cardinality: mandatory, one
	SnippetFromFileSPDXIdentifier DocElementID

	// 5.3: Snippet Byte Range: [start byte]:[end byte]
	// Cardinality: mandatory, one
	SnippetByteRangeStart int
	SnippetByteRangeEnd   int

	// 5.4: Snippet Line Range: [start line]:[end line]
	// Cardinality: optional, one
	SnippetLineRangeStart int
	SnippetLineRangeEnd   int

	// 5.5: Snippet Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	SnippetLicenseConcluded string

	// 5.6: License Information in Snippet: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: optional, one or many
	LicenseInfoInSnippet []string

	// 5.7: Snippet Comments on License
	// Cardinality: optional, one
	SnippetLicenseComments string

	// 5.8: Snippet Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	SnippetCopyrightText string

	// 5.9: Snippet Comment
	// Cardinality: optional, one
	SnippetComment string

	// 5.10: Snippet Name
	// Cardinality: optional, one
	SnippetName string

	// 5.11: Snippet Attribution Text
	// Cardinality: optional, one or many
	SnippetAttributionTexts []string
}

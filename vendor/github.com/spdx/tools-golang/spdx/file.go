// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package spdx

// File2_1 is a File section of an SPDX Document for version 2.1 of the spec.
type File2_1 struct {

	// 4.1: File Name
	// Cardinality: mandatory, one
	FileName string

	// 4.2: File SPDX Identifier: "SPDXRef-[idstring]"
	// Cardinality: mandatory, one
	FileSPDXIdentifier ElementID

	// 4.3: File Type
	// Cardinality: optional, multiple
	FileType []string

	// 4.4: File Checksum: may have keys for SHA1, SHA256 and/or MD5
	// Cardinality: mandatory, one SHA1, others may be optionally provided
	FileChecksumSHA1   string
	FileChecksumSHA256 string
	FileChecksumMD5    string

	// 4.5: Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	LicenseConcluded string

	// 4.6: License Information in File: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one or many
	LicenseInfoInFile []string

	// 4.7: Comments on License
	// Cardinality: optional, one
	LicenseComments string

	// 4.8: Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	FileCopyrightText string

	// DEPRECATED in version 2.1 of spec
	// 4.9-4.11: Artifact of Project variables (defined below)
	// Cardinality: optional, one or many
	ArtifactOfProjects []*ArtifactOfProject2_1

	// 4.12: File Comment
	// Cardinality: optional, one
	FileComment string

	// 4.13: File Notice
	// Cardinality: optional, one
	FileNotice string

	// 4.14: File Contributor
	// Cardinality: optional, one or many
	FileContributor []string

	// DEPRECATED in version 2.0 of spec
	// 4.15: File Dependencies
	// Cardinality: optional, one or many
	FileDependencies []string

	// Snippets contained in this File
	// Note that Snippets could be defined in a different Document! However,
	// the only ones that _THIS_ document can contain are this ones that are
	// defined here -- so this should just be an ElementID.
	Snippets map[ElementID]*Snippet2_1
}

// ArtifactOfProject2_1 is a DEPRECATED collection of data regarding
// a Package, as defined in sections 4.9-4.11 in version 2.1 of the spec.
type ArtifactOfProject2_1 struct {

	// DEPRECATED in version 2.1 of spec
	// 4.9: Artifact of Project Name
	// Cardinality: conditional, required if present, one per AOP
	Name string

	// DEPRECATED in version 2.1 of spec
	// 4.10: Artifact of Project Homepage: URL or "UNKNOWN"
	// Cardinality: optional, one per AOP
	HomePage string

	// DEPRECATED in version 2.1 of spec
	// 4.11: Artifact of Project Uniform Resource Identifier
	// Cardinality: optional, one per AOP
	URI string
}

// File2_2 is a File section of an SPDX Document for version 2.2 of the spec.
type File2_2 struct {

	// 4.1: File Name
	// Cardinality: mandatory, one
	FileName string

	// 4.2: File SPDX Identifier: "SPDXRef-[idstring]"
	// Cardinality: mandatory, one
	FileSPDXIdentifier ElementID

	// 4.3: File Type
	// Cardinality: optional, multiple
	FileType []string

	// 4.4: File Checksum: may have keys for SHA1, SHA256 and/or MD5
	// Cardinality: mandatory, one SHA1, others may be optionally provided
	FileChecksums map[ChecksumAlgorithm]Checksum

	// 4.5: Concluded License: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	LicenseConcluded string

	// 4.6: License Information in File: SPDX License Expression, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one or many
	LicenseInfoInFile []string

	// 4.7: Comments on License
	// Cardinality: optional, one
	LicenseComments string

	// 4.8: Copyright Text: copyright notice(s) text, "NONE" or "NOASSERTION"
	// Cardinality: mandatory, one
	FileCopyrightText string

	// DEPRECATED in version 2.1 of spec
	// 4.9-4.11: Artifact of Project variables (defined below)
	// Cardinality: optional, one or many
	ArtifactOfProjects []*ArtifactOfProject2_2

	// 4.12: File Comment
	// Cardinality: optional, one
	FileComment string

	// 4.13: File Notice
	// Cardinality: optional, one
	FileNotice string

	// 4.14: File Contributor
	// Cardinality: optional, one or many
	FileContributor []string

	// 4.15: File Attribution Text
	// Cardinality: optional, one or many
	FileAttributionTexts []string

	// DEPRECATED in version 2.0 of spec
	// 4.16: File Dependencies
	// Cardinality: optional, one or many
	FileDependencies []string

	// Snippets contained in this File
	// Note that Snippets could be defined in a different Document! However,
	// the only ones that _THIS_ document can contain are this ones that are
	// defined here -- so this should just be an ElementID.
	Snippets map[ElementID]*Snippet2_2
}

// ArtifactOfProject2_2 is a DEPRECATED collection of data regarding
// a Package, as defined in sections 4.9-4.11 in version 2.2 of the spec.
type ArtifactOfProject2_2 struct {

	// DEPRECATED in version 2.1 of spec
	// 4.9: Artifact of Project Name
	// Cardinality: conditional, required if present, one per AOP
	Name string

	// DEPRECATED in version 2.1 of spec
	// 4.10: Artifact of Project Homepage: URL or "UNKNOWN"
	// Cardinality: optional, one per AOP
	HomePage string

	// DEPRECATED in version 2.1 of spec
	// 4.11: Artifact of Project Uniform Resource Identifier
	// Cardinality: optional, one per AOP
	URI string
}

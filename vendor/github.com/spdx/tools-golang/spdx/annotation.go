// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package spdx

// Annotation2_1 is an Annotation section of an SPDX Document for version 2.1 of the spec.
type Annotation2_1 struct {

	// 8.1: Annotator
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	Annotator string
	// including AnnotatorType: one of "Person", "Organization" or "Tool"
	AnnotatorType string

	// 8.2: Annotation Date: YYYY-MM-DDThh:mm:ssZ
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationDate string

	// 8.3: Annotation Type: "REVIEW" or "OTHER"
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationType string

	// 8.4: SPDX Identifier Reference
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationSPDXIdentifier DocElementID

	// 8.5: Annotation Comment
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationComment string
}

// Annotation2_2 is an Annotation section of an SPDX Document for version 2.2 of the spec.
type Annotation2_2 struct {

	// 8.1: Annotator
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	Annotator string
	// including AnnotatorType: one of "Person", "Organization" or "Tool"
	AnnotatorType string

	// 8.2: Annotation Date: YYYY-MM-DDThh:mm:ssZ
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationDate string

	// 8.3: Annotation Type: "REVIEW" or "OTHER"
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationType string

	// 8.4: SPDX Identifier Reference
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationSPDXIdentifier DocElementID

	// 8.5: Annotation Comment
	// Cardinality: conditional (mandatory, one) if there is an Annotation
	AnnotationComment string
}

// Package spdxlib contains convenience and utility functions for working
// with an SPDX document that has already been created in memory.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
package spdxlib

import (
	"fmt"
	"github.com/spdx/tools-golang/spdx"
)

// GetDescribedPackageIDs2_1 returns a slice of ElementIDs for all Packages
// in this Document that it "describes," according to SPDX rules:
// - If the document has only one Package, its ID is returned.
// - If the document has 2+ Packages, it returns the IDs of those that have
//   a DESCRIBES (or DESCRIBED_BY) relationship to this DOCUMENT.
func GetDescribedPackageIDs2_1(doc *spdx.Document2_1) ([]spdx.ElementID, error) {
	// if nil Packages map or zero packages in it, return empty slice
	if doc.Packages == nil {
		return nil, fmt.Errorf("Packages map is nil")
	}
	if len(doc.Packages) == 0 {
		return nil, fmt.Errorf("no Packages in Document")
	}
	if len(doc.Packages) == 1 {
		// get first (only) one and return its ID
		for i := range doc.Packages {
			return []spdx.ElementID{i}, nil
		}
	}

	// two or more packages, so we need to go through the relationships,
	// find DESCRIBES or DESCRIBED_BY for this DOCUMENT, verify they are
	// valid IDs in this document's packages, and return them
	if doc.Relationships == nil {
		return nil, fmt.Errorf("multiple Packages in Document but Relationships slice is nil")
	}

	eIDs, err := FilterRelationships2_1(doc, func(relationship *spdx.Relationship2_1) *spdx.ElementID {
		refDocument := spdx.MakeDocElementID("", "DOCUMENT")

		if relationship.Relationship == "DESCRIBES" && relationship.RefA == refDocument {
			return &relationship.RefB.ElementRefID
		} else if relationship.Relationship == "DESCRIBED_BY" && relationship.RefB == refDocument {
			return &relationship.RefA.ElementRefID
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(eIDs) == 0 {
		return nil, fmt.Errorf("no DESCRIBES or DESCRIBED_BY relationships found for this Document")
	}

	eIDs = SortElementIDs(eIDs)

	return eIDs, nil
}

// GetDescribedPackageIDs2_2 returns a slice of ElementIDs for all Packages
// in this Document that it "describes," according to SPDX rules:
// - If the document has only one Package, its ID is returned.
// - If the document has 2+ Packages, it returns the IDs of those that have
//   a DESCRIBES (or DESCRIBED_BY) relationship to this DOCUMENT.
func GetDescribedPackageIDs2_2(doc *spdx.Document2_2) ([]spdx.ElementID, error) {
	// if nil Packages map or zero packages in it, return empty slice
	if doc.Packages == nil {
		return nil, fmt.Errorf("Packages map is nil")
	}
	if len(doc.Packages) == 0 {
		return nil, fmt.Errorf("no Packages in Document")
	}
	if len(doc.Packages) == 1 {
		// get first (only) one and return its ID
		for i := range doc.Packages {
			return []spdx.ElementID{i}, nil
		}
	}

	// two or more packages, so we need to go through the relationships,
	// find DESCRIBES or DESCRIBED_BY for this DOCUMENT, verify they are
	// valid IDs in this document's packages, and return them
	if doc.Relationships == nil {
		return nil, fmt.Errorf("multiple Packages in Document but Relationships slice is nil")
	}

	eIDs, err := FilterRelationships2_2(doc, func(relationship *spdx.Relationship2_2) *spdx.ElementID {
		refDocument := spdx.MakeDocElementID("", "DOCUMENT")

		if relationship.Relationship == "DESCRIBES" && relationship.RefA == refDocument {
			return &relationship.RefB.ElementRefID
		} else if relationship.Relationship == "DESCRIBED_BY" && relationship.RefB == refDocument {
			return &relationship.RefA.ElementRefID
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(eIDs) == 0 {
		return nil, fmt.Errorf("no DESCRIBES or DESCRIBED_BY relationships found for this Document")
	}

	eIDs = SortElementIDs(eIDs)

	return eIDs, nil
}

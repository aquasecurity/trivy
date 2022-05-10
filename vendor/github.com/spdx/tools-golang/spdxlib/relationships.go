// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package spdxlib

import "github.com/spdx/tools-golang/spdx"

// FilterRelationships2_1 returns a slice of Element IDs returned by the given filter closure. The closure is passed
// one relationship at a time, and it can return an ElementID or nil.
func FilterRelationships2_1(doc *spdx.Document2_1, filter func(*spdx.Relationship2_1) *spdx.ElementID) ([]spdx.ElementID, error) {
	elementIDs := []spdx.ElementID{}

	for _, relationship := range doc.Relationships {
		if id := filter(relationship); id != nil {
			elementIDs = append(elementIDs, *id)
		}
	}

	return elementIDs, nil
}

// FilterRelationships2_2 returns a slice of Element IDs returned by the given filter closure. The closure is passed
// one relationship at a time, and it can return an ElementID or nil.
func FilterRelationships2_2(doc *spdx.Document2_2, filter func(*spdx.Relationship2_2) *spdx.ElementID) ([]spdx.ElementID, error) {
	elementIDs := []spdx.ElementID{}

	for _, relationship := range doc.Relationships {
		if id := filter(relationship); id != nil {
			elementIDs = append(elementIDs, *id)
		}
	}

	return elementIDs, nil
}

// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"github.com/spdx/tools-golang/spdx"
)

func renderRelationships2_2(relationships []*spdx.Relationship2_2, jsondocument map[string]interface{}) ([]interface{}, error) {

	var rels []interface{}
	for _, v := range relationships {
		rel := make(map[string]interface{})
		if len(v.RefA.ElementRefID) != 0 || len(v.RefA.DocumentRefID) != 0 {
			rel["spdxElementId"] = spdx.RenderDocElementID(v.RefA)
		}
		if len(v.RefB.ElementRefID) != 0 || len(v.RefB.DocumentRefID) != 0 {
			rel["relatedSpdxElement"] = spdx.RenderDocElementID(v.RefB)
		}
		if v.Relationship != "" {
			rel["relationshipType"] = v.Relationship
		}
		if v.RelationshipComment != "" {
			rel["comment"] = v.RelationshipComment
		}
		rels = append(rels, rel)
	}
	if len(rels) > 0 {
		jsondocument["relationships"] = rels
	}
	return rels, nil
}

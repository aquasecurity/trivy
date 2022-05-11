// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonRelationships2_2(key string, value interface{}, doc *spdxDocument2_2) error {

	//FIXME : NOASSERTION and NONE in relationship B value not compatible
	if reflect.TypeOf(value).Kind() == reflect.Slice {
		relationships := reflect.ValueOf(value)
		for i := 0; i < relationships.Len(); i++ {
			relationship := relationships.Index(i).Interface().(map[string]interface{})
			rel := spdx.Relationship2_2{}
			// Parse ref A of the relationship
			aid, err := extractDocElementID(relationship["spdxElementId"].(string))
			if err != nil {
				return fmt.Errorf("%s", err)
			}
			rel.RefA = aid

			// Parse the refB of the relationship
			// NONE and NOASSERTION are permitted on right side
			permittedSpecial := []string{"NONE", "NOASSERTION"}
			bid, err := extractDocElementSpecial(relationship["relatedSpdxElement"].(string), permittedSpecial)
			if err != nil {
				return fmt.Errorf("%s", err)
			}
			rel.RefB = bid
			// Parse relationship type
			if relationship["relationshipType"] == nil {
				return fmt.Errorf("%s , %d", "RelationshipType propty missing in relationship number", i)
			}
			rel.Relationship = relationship["relationshipType"].(string)

			// Parse the relationship comment
			if relationship["comment"] != nil {
				rel.RelationshipComment = relationship["comment"].(string)
			}

			doc.Relationships = append(doc.Relationships, &rel)
		}

	}
	return nil
}

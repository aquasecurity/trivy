// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonReviews2_2(key string, value interface{}, doc *spdxDocument2_2) error {
	//FIXME: Reviewer type property of review not specified in the spec
	if reflect.TypeOf(value).Kind() == reflect.Slice {
		reviews := reflect.ValueOf(value)
		for i := 0; i < reviews.Len(); i++ {
			reviewmap := reviews.Index(i).Interface().(map[string]interface{})
			review := spdx.Review2_2{}
			// Remove loop all properties are mandatory in annotations
			for k, v := range reviewmap {
				switch k {
				case "reviewer":
					subkey, subvalue, err := extractSubs(v.(string))
					if err != nil {
						return err
					}
					if subkey != "Person" && subkey != "Organization" && subkey != "Tool" {
						return fmt.Errorf("unrecognized Reviewer type %v", subkey)
					}
					review.ReviewerType = subkey
					review.Reviewer = subvalue
				case "comment":
					review.ReviewComment = v.(string)
				case "reviewDate":
					review.ReviewDate = v.(string)
				default:
					return fmt.Errorf("received unknown tag %v in Review Section section", k)
				}
			}
			doc.Reviews = append(doc.Reviews, &review)
		}

	}
	return nil
}

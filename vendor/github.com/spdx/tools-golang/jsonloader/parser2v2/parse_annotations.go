// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonAnnotations2_2(key string, value interface{}, doc *spdxDocument2_2, SPDXElementId spdx.DocElementID) error {
	//FIXME: SPDXID property not defined in spec but it is needed
	if reflect.TypeOf(value).Kind() == reflect.Slice {
		annotations := reflect.ValueOf(value)
		for i := 0; i < annotations.Len(); i++ {
			annotation := annotations.Index(i).Interface().(map[string]interface{})
			ann := spdx.Annotation2_2{AnnotationSPDXIdentifier: SPDXElementId}
			// Remove loop all properties are mandatory in annotations
			for k, v := range annotation {
				switch k {
				case "annotationDate":
					ann.AnnotationDate = v.(string)
				case "annotationType":
					ann.AnnotationType = v.(string)
				case "comment":
					ann.AnnotationComment = v.(string)
				case "annotator":
					subkey, subvalue, err := extractSubs(v.(string))
					if err != nil {
						return err
					}
					if subkey != "Person" && subkey != "Organization" && subkey != "Tool" {
						return fmt.Errorf("unrecognized Annotator type %v", subkey)
					}
					ann.AnnotatorType = subkey
					ann.Annotator = subvalue

				default:
					return fmt.Errorf("received unknown tag %v in Annotation section", k)
				}
			}
			doc.Annotations = append(doc.Annotations, &ann)
		}

	}
	return nil
}

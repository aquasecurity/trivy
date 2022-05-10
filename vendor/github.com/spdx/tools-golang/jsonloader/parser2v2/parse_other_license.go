// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonOtherLicenses2_2(key string, value interface{}, doc *spdxDocument2_2) error {
	if reflect.TypeOf(value).Kind() == reflect.Slice {
		otherlicenses := reflect.ValueOf(value)
		for i := 0; i < otherlicenses.Len(); i++ {
			licensemap := otherlicenses.Index(i).Interface().(map[string]interface{})
			license := spdx.OtherLicense2_2{}
			// Remove loop all properties are mandatory in annotations
			for k, v := range licensemap {
				switch k {
				case "licenseId":
					license.LicenseIdentifier = v.(string)
				case "extractedText":
					license.ExtractedText = v.(string)
				case "name":
					license.LicenseName = v.(string)
				case "comment":
					license.LicenseComment = v.(string)
				case "seeAlsos":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						texts := reflect.ValueOf(v)
						for i := 0; i < texts.Len(); i++ {
							license.LicenseCrossReferences = append(license.LicenseCrossReferences, texts.Index(i).Interface().(string))
						}
					}
				default:
					return fmt.Errorf("received unknown tag %v in Licenses section", k)
				}
			}
			doc.OtherLicenses = append(doc.OtherLicenses, &license)
		}

	}
	return nil
}

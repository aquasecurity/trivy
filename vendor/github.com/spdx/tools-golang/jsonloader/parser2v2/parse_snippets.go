// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonSnippets2_2(key string, value interface{}, doc *spdxDocument2_2) error {

	if reflect.TypeOf(value).Kind() == reflect.Slice {
		snippets := reflect.ValueOf(value)
		for i := 0; i < snippets.Len(); i++ {
			snippetmap := snippets.Index(i).Interface().(map[string]interface{})
			// create a new package
			snippet := &spdx.Snippet2_2{}
			//extract the SPDXID of the package
			eID, err := extractElementID(snippetmap["SPDXID"].(string))
			if err != nil {
				return fmt.Errorf("%s", err)
			}
			snippet.SnippetSPDXIdentifier = eID
			//range over all other properties now
			for k, v := range snippetmap {
				switch k {
				case "SPDXID", "snippetFromFile":
					//redundant case
				case "name":
					snippet.SnippetName = v.(string)
				case "copyrightText":
					snippet.SnippetCopyrightText = v.(string)
				case "licenseComments":
					snippet.SnippetLicenseComments = v.(string)
				case "licenseConcluded":
					snippet.SnippetLicenseConcluded = v.(string)
				case "licenseInfoInSnippets":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							snippet.LicenseInfoInSnippet = append(snippet.LicenseInfoInSnippet, info.Index(i).Interface().(string))
						}
					}
				case "attributionTexts":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							snippet.SnippetAttributionTexts = append(snippet.SnippetAttributionTexts, info.Index(i).Interface().(string))
						}
					}
				case "comment":
					snippet.SnippetComment = v.(string)
				case "ranges":
					//TODO: optimise this logic
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							ranges := info.Index(i).Interface().(map[string]interface{})
							rangeStart := ranges["startPointer"].(map[string]interface{})
							rangeEnd := ranges["endPointer"].(map[string]interface{})
							if rangeStart["lineNumber"] != nil && rangeEnd["lineNumber"] != nil {
								snippet.SnippetLineRangeStart = int(rangeStart["lineNumber"].(float64))
								snippet.SnippetLineRangeEnd = int(rangeEnd["lineNumber"].(float64))
							} else {
								snippet.SnippetByteRangeStart = int(rangeStart["offset"].(float64))
								snippet.SnippetByteRangeEnd = int(rangeEnd["offset"].(float64))
							}
						}
					}
				default:
					return fmt.Errorf("received unknown tag %v in snippet section", k)
				}
			}
			fileID, err2 := extractDocElementID(snippetmap["snippetFromFile"].(string))
			if err2 != nil {
				return fmt.Errorf("%s", err2)
			}
			snippet.SnippetFromFileSPDXIdentifier = fileID
			if doc.UnpackagedFiles[fileID.ElementRefID].Snippets == nil {
				doc.UnpackagedFiles[fileID.ElementRefID].Snippets = make(map[spdx.ElementID]*spdx.Snippet2_2)
			}
			doc.UnpackagedFiles[fileID.ElementRefID].Snippets[eID] = snippet
		}

	}
	return nil
}

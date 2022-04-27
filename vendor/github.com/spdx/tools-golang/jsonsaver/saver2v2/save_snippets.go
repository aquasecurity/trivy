// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"sort"

	"github.com/spdx/tools-golang/spdx"
)

func renderSnippets2_2(jsondocument map[string]interface{}, allfiles map[spdx.ElementID]*spdx.File2_2) ([]interface{}, error) {

	var snippets []interface{}
	for _, value := range allfiles {
		snippet := make(map[string]interface{})

		var keys []string
		for ke := range value.Snippets {
			keys = append(keys, string(ke))
		}
		sort.Strings(keys)
		for _, k := range keys {
			v := value.Snippets[spdx.ElementID(k)]
			snippet["SPDXID"] = spdx.RenderElementID(v.SnippetSPDXIdentifier)
			if v.SnippetComment != "" {
				snippet["comment"] = v.SnippetComment
			}
			if v.SnippetCopyrightText != "" {
				snippet["copyrightText"] = v.SnippetCopyrightText
			}
			if v.SnippetLicenseComments != "" {
				snippet["licenseComments"] = v.SnippetLicenseComments
			}
			if v.SnippetLicenseConcluded != "" {
				snippet["licenseConcluded"] = v.SnippetLicenseConcluded
			}
			if v.LicenseInfoInSnippet != nil {
				snippet["licenseInfoInSnippets"] = v.LicenseInfoInSnippet
			}
			if v.SnippetName != "" {
				snippet["name"] = v.SnippetName
			}
			if v.SnippetName != "" {
				snippet["snippetFromFile"] = spdx.RenderDocElementID(v.SnippetFromFileSPDXIdentifier)
			}
			if v.SnippetAttributionTexts != nil {
				snippet["attributionTexts"] = v.SnippetAttributionTexts
			}

			// save  snippet ranges
			var ranges []interface{}

			byterange := map[string]interface{}{
				"endPointer": map[string]interface{}{
					"offset":    v.SnippetByteRangeEnd,
					"reference": spdx.RenderDocElementID(v.SnippetFromFileSPDXIdentifier),
				},
				"startPointer": map[string]interface{}{
					"offset":    v.SnippetByteRangeStart,
					"reference": spdx.RenderDocElementID(v.SnippetFromFileSPDXIdentifier),
				},
			}
			linerange := map[string]interface{}{
				"endPointer": map[string]interface{}{
					"lineNumber": v.SnippetLineRangeEnd,
					"reference":  spdx.RenderDocElementID(v.SnippetFromFileSPDXIdentifier),
				},
				"startPointer": map[string]interface{}{
					"lineNumber": v.SnippetLineRangeStart,
					"reference":  spdx.RenderDocElementID(v.SnippetFromFileSPDXIdentifier),
				},
			}
			if len(byterange) > 0 {
				ranges = append(ranges, byterange)
			}
			if len(linerange) > 0 {
				ranges = append(ranges, linerange)
			}
			snippet["ranges"] = ranges
			snippets = append(snippets, snippet)
		}
	}
	if len(snippets) > 0 {
		jsondocument["snippets"] = snippets
	}
	return snippets, nil
}

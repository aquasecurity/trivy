// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"fmt"

	"github.com/spdx/tools-golang/spdx"
)

func renderCreationInfo2_2(ci *spdx.CreationInfo2_2, jsondocument map[string]interface{}) error {
	if ci.SPDXIdentifier != "" {
		jsondocument["SPDXID"] = spdx.RenderElementID(ci.SPDXIdentifier)
	}
	if ci.SPDXVersion != "" {
		jsondocument["spdxVersion"] = ci.SPDXVersion
	}
	if ci.CreatorComment != "" || ci.Created != "" || ci.CreatorPersons != nil || ci.CreatorOrganizations != nil || ci.CreatorTools != nil || ci.LicenseListVersion != "" {
		creationInfo := make(map[string]interface{})
		if ci.CreatorComment != "" {
			creationInfo["comment"] = ci.CreatorComment
		}
		if ci.Created != "" {
			creationInfo["created"] = ci.Created

		}
		if ci.CreatorPersons != nil || ci.CreatorOrganizations != nil || ci.CreatorTools != nil {
			var creators []string
			for _, v := range ci.CreatorTools {
				creators = append(creators, fmt.Sprintf("Tool: %s", v))
			}
			for _, v := range ci.CreatorOrganizations {
				creators = append(creators, fmt.Sprintf("Organization: %s", v))
			}
			for _, v := range ci.CreatorPersons {
				creators = append(creators, fmt.Sprintf("Person: %s", v))
			}

			creationInfo["creators"] = creators
		}
		if ci.LicenseListVersion != "" {
			creationInfo["licenseListVersion"] = ci.LicenseListVersion
		}
		jsondocument["creationInfo"] = creationInfo
	}
	if ci.DocumentName != "" {
		jsondocument["name"] = ci.DocumentName
	}
	if ci.DataLicense != "" {
		jsondocument["dataLicense"] = ci.DataLicense
	}
	if ci.DocumentComment != "" {
		jsondocument["comment"] = ci.DocumentComment
	}
	if ci.DocumentNamespace != "" {
		jsondocument["documentNamespace"] = ci.DocumentNamespace
	}

	if ci.ExternalDocumentReferences != nil {
		var refs []interface{}
		for _, v := range ci.ExternalDocumentReferences {
			aa := make(map[string]interface{})
			aa["externalDocumentId"] = fmt.Sprintf("DocumentRef-%s", v.DocumentRefID)
			aa["checksum"] = map[string]string{
				"algorithm":     v.Alg,
				"checksumValue": v.Checksum,
			}
			aa["spdxDocument"] = v.URI
			refs = append(refs, aa)
		}
		if len(refs) > 0 {
			jsondocument["externalDocumentRefs"] = refs
		}
	}

	return nil
}

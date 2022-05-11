// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"github.com/spdx/tools-golang/spdx"
)

func renderOtherLicenses2_2(otherlicenses []*spdx.OtherLicense2_2, jsondocument map[string]interface{}) ([]interface{}, error) {

	var licenses []interface{}
	for _, v := range otherlicenses {
		lic := make(map[string]interface{})
		if v.LicenseIdentifier != "" {
			lic["licenseId"] = v.LicenseIdentifier
		}
		if v.ExtractedText != "" {
			lic["extractedText"] = v.ExtractedText
		}
		if v.LicenseComment != "" {
			lic["comment"] = v.LicenseComment
		}
		if v.LicenseName != "" {
			lic["name"] = v.LicenseName
		}
		if v.LicenseCrossReferences != nil {
			lic["seeAlsos"] = v.LicenseCrossReferences
		}
		licenses = append(licenses, lic)
	}
	if len(licenses) > 0 {
		jsondocument["hasExtractedLicensingInfos"] = licenses
	}
	return licenses, nil
}

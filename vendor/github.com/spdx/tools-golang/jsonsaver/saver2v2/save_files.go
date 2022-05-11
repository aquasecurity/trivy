// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"sort"

	"github.com/spdx/tools-golang/spdx"
)

func renderFiles2_2(doc *spdx.Document2_2, jsondocument map[string]interface{}, allfiles map[spdx.ElementID]*spdx.File2_2) ([]interface{}, error) {

	var keys []string
	for ke := range allfiles {
		keys = append(keys, string(ke))
	}
	sort.Strings(keys)

	var files []interface{}
	for _, k := range keys {
		v := allfiles[spdx.ElementID(k)]
		file := make(map[string]interface{})
		file["SPDXID"] = spdx.RenderElementID(spdx.ElementID(k))
		ann, _ := renderAnnotations2_2(doc.Annotations, spdx.MakeDocElementID("", string(v.FileSPDXIdentifier)))
		if ann != nil {
			file["annotations"] = ann
		}
		if v.FileContributor != nil {
			file["fileContributors"] = v.FileContributor
		}
		if v.FileComment != "" {
			file["comment"] = v.FileComment
		}

		// save package checksums
		if v.FileChecksums != nil {
			var checksums []interface{}

			var algos []string
			for alg := range v.FileChecksums {
				algos = append(algos, string(alg))
			}
			sort.Strings(algos)

			// for _, value := range v.FileChecksums {
			for _, algo := range algos {
				value := v.FileChecksums[spdx.ChecksumAlgorithm(algo)]
				checksum := make(map[string]interface{})
				checksum["algorithm"] = string(value.Algorithm)
				checksum["checksumValue"] = value.Value
				checksums = append(checksums, checksum)
			}
			file["checksums"] = checksums
		}
		if v.FileCopyrightText != "" {
			file["copyrightText"] = v.FileCopyrightText
		}
		if v.FileName != "" {
			file["fileName"] = v.FileName
		}
		if v.FileType != nil {
			file["fileTypes"] = v.FileType
		}
		if v.LicenseComments != "" {
			file["licenseComments"] = v.LicenseComments
		}
		if v.LicenseConcluded != "" {
			file["licenseConcluded"] = v.LicenseConcluded
		}
		if v.LicenseInfoInFile != nil {
			file["licenseInfoInFiles"] = v.LicenseInfoInFile
		}
		if v.FileNotice != "" {
			file["noticeText"] = v.FileNotice
		}
		if v.FileDependencies != nil {
			file["fileDependencies"] = v.FileDependencies
		}
		if v.FileAttributionTexts != nil {
			file["attributionTexts"] = v.FileAttributionTexts
		}

		files = append(files, file)
	}
	if len(files) > 0 {
		jsondocument["files"] = files
	}
	return files, nil
}

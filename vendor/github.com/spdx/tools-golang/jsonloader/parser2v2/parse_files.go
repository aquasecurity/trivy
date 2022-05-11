// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"

	"github.com/spdx/tools-golang/spdx"
)

//TODO: check whether file can contain annotations or not
func (spec JSONSpdxDocument) parseJsonFiles2_2(key string, value interface{}, doc *spdxDocument2_2) error {

	if doc.UnpackagedFiles == nil {
		doc.UnpackagedFiles = map[spdx.ElementID]*spdx.File2_2{}
	}

	if reflect.TypeOf(value).Kind() == reflect.Slice {
		files := reflect.ValueOf(value)
		for i := 0; i < files.Len(); i++ {
			filemap := files.Index(i).Interface().(map[string]interface{})
			// create a new package
			file := &spdx.File2_2{}
			//extract the SPDXID of the package
			eID, err := extractElementID(filemap["SPDXID"].(string))
			if err != nil {
				return fmt.Errorf("%s", err)
			}
			file.FileSPDXIdentifier = eID
			//range over all other properties now
			for k, v := range filemap {
				switch k {
				case "SPDXID":
					//redundant case
				case "fileName":
					file.FileName = v.(string)
				case "fileTypes":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						texts := reflect.ValueOf(v)
						for i := 0; i < texts.Len(); i++ {
							file.FileType = append(file.FileType, texts.Index(i).Interface().(string))
						}
					}
				case "checksums":
					//general function to parse checksums in utils
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						checksums := reflect.ValueOf(v)
						if file.FileChecksums == nil {
							file.FileChecksums = make(map[spdx.ChecksumAlgorithm]spdx.Checksum)
						}
						for i := 0; i < checksums.Len(); i++ {
							checksum := checksums.Index(i).Interface().(map[string]interface{})
							switch checksum["algorithm"].(string) {
							case spdx.SHA1, spdx.SHA256, spdx.MD5:
								algorithm := spdx.ChecksumAlgorithm(checksum["algorithm"].(string))
								file.FileChecksums[algorithm] = spdx.Checksum{Algorithm: algorithm, Value: checksum["checksumValue"].(string)}
							default:
								return fmt.Errorf("got unknown checksum type %s", checksum["algorithm"])
							}
						}
					}
				case "annotations":
					id, err := extractDocElementID(filemap["SPDXID"].(string))
					if err != nil {
						return fmt.Errorf("%s", err)
					}
					err = spec.parseJsonAnnotations2_2(k, v, doc, id)
					if err != nil {
						return err
					}
				case "copyrightText":
					file.FileCopyrightText = v.(string)
				case "noticeText":
					file.FileNotice = v.(string)
				case "licenseComments":
					file.LicenseComments = v.(string)
				case "licenseConcluded":
					file.LicenseConcluded = v.(string)
				case "licenseInfoInFiles":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							file.LicenseInfoInFile = append(file.LicenseInfoInFile, info.Index(i).Interface().(string))
						}
					}
				case "fileContributors":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							file.FileContributor = append(file.FileContributor, info.Index(i).Interface().(string))
						}
					}
				case "fileDependencies":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							file.FileDependencies = append(file.FileDependencies, info.Index(i).Interface().(string))
						}
					}
				case "attributionTexts":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							file.FileAttributionTexts = append(file.FileAttributionTexts, info.Index(i).Interface().(string))
						}
					}
				case "comment":
					file.FileComment = v.(string)

				default:
					return fmt.Errorf("received unknown tag %v in files section", k)
				}
			}
			doc.UnpackagedFiles[eID] = file
		}

	}
	return nil
}

//relationship comment property

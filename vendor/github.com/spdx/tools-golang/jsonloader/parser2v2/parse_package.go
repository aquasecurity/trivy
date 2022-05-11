// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonPackages2_2(key string, value interface{}, doc *spdxDocument2_2) error {

	if doc.Packages == nil {
		doc.Packages = map[spdx.ElementID]*spdx.Package2_2{}
	}

	if reflect.TypeOf(value).Kind() == reflect.Slice {
		packages := reflect.ValueOf(value)
		for i := 0; i < packages.Len(); i++ {
			pack := packages.Index(i).Interface().(map[string]interface{})
			// create a new package
			pkg := &spdx.Package2_2{
				FilesAnalyzed:             true,
				IsFilesAnalyzedTagPresent: false,
			}
			//extract the SPDXID of the package
			eID, err := extractElementID(pack["SPDXID"].(string))
			if err != nil {
				return fmt.Errorf("%s", err)
			}
			pkg.PackageSPDXIdentifier = eID
			//range over all other properties now
			for k, v := range pack {
				switch k {
				case "SPDXID":
					//redundant case
				case "name":
					pkg.PackageName = v.(string)
				case "annotations":
					packageId, err := extractDocElementID(pack["SPDXID"].(string))
					if err != nil {
						return fmt.Errorf("%s", err)
					}
					//generalize function to parse annotations
					err = spec.parseJsonAnnotations2_2("annotations", v, doc, packageId)
					if err != nil {
						return err
					}
				case "attributionTexts":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						texts := reflect.ValueOf(v)
						for i := 0; i < texts.Len(); i++ {
							pkg.PackageAttributionTexts = append(pkg.PackageAttributionTexts, texts.Index(i).Interface().(string))
						}
					}
				case "checksums":
					//general function to parse checksums in utils
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						checksums := reflect.ValueOf(v)
						if pkg.PackageChecksums == nil {
							pkg.PackageChecksums = make(map[spdx.ChecksumAlgorithm]spdx.Checksum)
						}
						for i := 0; i < checksums.Len(); i++ {
							checksum := checksums.Index(i).Interface().(map[string]interface{})
							switch checksum["algorithm"].(string) {
							case spdx.SHA1, spdx.SHA256, spdx.MD5:
								algorithm := spdx.ChecksumAlgorithm(checksum["algorithm"].(string))
								pkg.PackageChecksums[algorithm] = spdx.Checksum{Algorithm: algorithm, Value: checksum["checksumValue"].(string)}
							default:
								return fmt.Errorf("got unknown checksum type %s", checksum["algorithm"])
							}
						}
					}
				case "copyrightText":
					pkg.PackageCopyrightText = v.(string)
				case "description":
					pkg.PackageDescription = v.(string)
				case "downloadLocation":
					pkg.PackageDownloadLocation = v.(string)
				case "externalRefs":
					//make a function to parse these
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						extrefs := reflect.ValueOf(v)
						for i := 0; i < extrefs.Len(); i++ {
							ref := extrefs.Index(i).Interface().(map[string]interface{})
							newref := &spdx.PackageExternalReference2_2{}
							//TODO: if either of these 3 missing then error
							newref.RefType = ref["referenceType"].(string)
							newref.Locator = ref["referenceLocator"].(string)
							newref.Category = ref["referenceCategory"].(string)
							if ref["comment"] != nil {
								newref.ExternalRefComment = ref["comment"].(string)
							}
							pkg.PackageExternalReferences = append(pkg.PackageExternalReferences, newref)
						}
					}
				case "filesAnalyzed":
					pkg.IsFilesAnalyzedTagPresent = true
					if !v.(bool) {
						pkg.FilesAnalyzed = false
					} else {
						pkg.FilesAnalyzed = true
					}
				case "homepage":
					pkg.PackageHomePage = v.(string)
				case "licenseComments":
					pkg.PackageLicenseComments = v.(string)
				case "licenseConcluded":
					pkg.PackageLicenseConcluded = v.(string)
				case "licenseDeclared":
					pkg.PackageLicenseDeclared = v.(string)
				case "licenseInfoFromFiles":
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						info := reflect.ValueOf(v)
						for i := 0; i < info.Len(); i++ {
							pkg.PackageLicenseInfoFromFiles = append(pkg.PackageLicenseInfoFromFiles, info.Index(i).Interface().(string))
						}
					}
				case "originator":
					if v.(string) == "NOASSERTION" {
						pkg.PackageOriginatorNOASSERTION = true
						break
					}
					subkey, subvalue, err := extractSubs(v.(string))
					if err != nil {
						return err
					}
					switch subkey {
					case "Person":
						pkg.PackageOriginatorPerson = subvalue
					case "Organization":
						pkg.PackageOriginatorOrganization = subvalue
					default:
						return fmt.Errorf("unrecognized PackageOriginator type %v", subkey)
					}
				case "packageFileName":
					pkg.PackageFileName = v.(string)
				case "packageVerificationCode":
					code := v.(map[string]interface{})
					for codekey, codeval := range code {
						switch codekey {
						case "packageVerificationCodeExcludedFiles":
							if reflect.TypeOf(codeval).Kind() == reflect.Slice {
								efiles := reflect.ValueOf(codeval)
								filename := efiles.Index(0).Interface().(string)
								if strings.HasPrefix(filename, "excludes:") {
									_, filename, err = extractSubs(efiles.Index(0).Interface().(string))
									if err != nil {
										return fmt.Errorf("%s", err)
									}
								}
								pkg.PackageVerificationCodeExcludedFile = strings.Trim(filename, " ")
							}
						case "packageVerificationCodeValue":
							pkg.PackageVerificationCode = code["packageVerificationCodeValue"].(string)
						}
					}
				case "sourceInfo":
					pkg.PackageSourceInfo = v.(string)
				case "summary":
					pkg.PackageSummary = v.(string)
				case "supplier":
					if v.(string) == "NOASSERTION" {
						pkg.PackageSupplierNOASSERTION = true
						break
					}
					subkey, subvalue, err := extractSubs(v.(string))
					if err != nil {
						return err
					}
					switch subkey {
					case "Person":
						pkg.PackageSupplierPerson = subvalue
					case "Organization":
						pkg.PackageSupplierOrganization = subvalue
					default:
						return fmt.Errorf("unrecognized PackageSupplier type %v", subkey)
					}

				case "versionInfo":
					pkg.PackageVersion = v.(string)
				case "comment":
					pkg.PackageComment = v.(string)
				case "hasFiles":
					if pkg.Files == nil {
						pkg.Files = make(map[spdx.ElementID]*spdx.File2_2)
					}
					if reflect.TypeOf(v).Kind() == reflect.Slice {
						SpdxIds := reflect.ValueOf(v)
						for i := 0; i < SpdxIds.Len(); i++ {
							fileId, err := extractElementID(SpdxIds.Index(i).Interface().(string))
							if err != nil {
								return err
							}
							pkg.Files[fileId] = doc.UnpackagedFiles[fileId]
							delete(doc.UnpackagedFiles, fileId)
						}
					}

				default:
					return fmt.Errorf("received unknown tag %v in Annotation section", k)
				}
			}
			doc.Packages[eID] = pkg
		}

	}
	return nil
}

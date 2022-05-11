// Package jsonloader is used to load and parse SPDX JSON documents
// into tools-golang data structures.
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"encoding/json"
	"fmt"

	"github.com/spdx/tools-golang/spdx"
)

//TODO : return spdx.Document2_2
func Load2_2(content []byte) (*spdx.Document2_2, error) {
	// check whetehr the Json is valid or not
	if !json.Valid(content) {
		return nil, fmt.Errorf("%s", "Invalid JSON Specification")
	}
	result := spdxDocument2_2{}
	// unmarshall the json into the result struct
	err := json.Unmarshal(content, &result)
	resultfinal := spdx.Document2_2(result)

	if err != nil {
		return nil, fmt.Errorf("%s", err)
	}

	return &resultfinal, nil
}

func (doc *spdxDocument2_2) UnmarshalJSON(data []byte) error {
	var specs JSONSpdxDocument
	//unmarshall the json into the intermediate stricture map[string]interface{}
	err := json.Unmarshal(data, &specs)
	if err != nil {
		return err
	}
	// parse the data from the intermediate structure to the spdx.Document2_2{}
	err = specs.newDocument(doc)
	if err != nil {
		return err
	}
	return nil
}

func (spec JSONSpdxDocument) newDocument(doc *spdxDocument2_2) error {
	// raneg through all the keys in the map and send them to appropriate arsing functions
	for key, val := range spec {
		switch key {
		case "dataLicense", "spdxVersion", "SPDXID", "documentNamespace", "name", "comment", "creationInfo", "externalDocumentRefs":
			err := spec.parseJsonCreationInfo2_2(key, val, doc)
			if err != nil {
				return err
			}
		case "annotations":
			// if the json spec doenn't has any files then only this case will be executed
			if spec["files"] == nil {

				id, err := extractDocElementID(spec["SPDXID"].(string))
				if err != nil {
					return fmt.Errorf("%s", err)
				}
				err = spec.parseJsonAnnotations2_2(key, val, doc, id)
				if err != nil {
					return err
				}
			}
		case "relationships":
			err := spec.parseJsonRelationships2_2(key, val, doc)
			if err != nil {
				return err
			}
		case "files":
			//first parse all the files
			err := spec.parseJsonFiles2_2(key, val, doc)
			if err != nil {
				return err
			}
			//then parse the snippets
			if spec["snippets"] != nil {
				err = spec.parseJsonSnippets2_2("snippets", spec["snippets"], doc)
				if err != nil {
					return err
				}
			}
			//then parse the packages
			if spec["packages"] != nil {
				err = spec.parseJsonPackages2_2("packages", spec["packages"], doc)
				if err != nil {
					return err
				}
			}
			// then parse the annotations
			if spec["annotations"] != nil {
				id, err := extractDocElementID(spec["SPDXID"].(string))
				if err != nil {
					return fmt.Errorf("%s", err)
				}
				err = spec.parseJsonAnnotations2_2("annotations", spec["annotations"], doc, id)
				if err != nil {
					return err
				}
			}

		case "packages":
			// if the json spec doesn't has any files to parse then this switch case will be executed
			if spec["files"] == nil {
				err := spec.parseJsonPackages2_2("packages", spec["packages"], doc)
				if err != nil {
					return err
				}
			}
		case "hasExtractedLicensingInfos":
			err := spec.parseJsonOtherLicenses2_2(key, val, doc)
			if err != nil {
				return err
			}
		case "revieweds":
			err := spec.parseJsonReviews2_2(key, val, doc)
			if err != nil {
				return err
			}
		case "snippets", "documentDescribes":
			//redundant case
		default:
			return fmt.Errorf("unrecognized key here %v", key)
		}

	}
	return nil
}

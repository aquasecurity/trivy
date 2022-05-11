// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package parser2v2

import (
	"fmt"
	"reflect"
	"strings"

	"github.com/spdx/tools-golang/spdx"
)

func (spec JSONSpdxDocument) parseJsonCreationInfo2_2(key string, value interface{}, doc *spdxDocument2_2) error {
	// create an SPDX Creation Info data struct if we don't have one already

	if doc.CreationInfo == nil {
		doc.CreationInfo = &spdx.CreationInfo2_2{
			ExternalDocumentReferences: map[string]spdx.ExternalDocumentRef2_2{},
		}
	}
	ci := doc.CreationInfo
	switch key {
	case "dataLicense":
		ci.DataLicense = value.(string)
	case "spdxVersion":
		ci.SPDXVersion = value.(string)
	case "SPDXID":
		id, err := extractElementID(value.(string))
		if err != nil {
			return fmt.Errorf("%s", err)
		}
		ci.SPDXIdentifier = id
	case "documentNamespace":
		ci.DocumentNamespace = value.(string)
	case "name":
		ci.DocumentName = value.(string)
	case "comment":
		ci.DocumentComment = value.(string)
	case "creationInfo":
		creationInfo := value.(map[string]interface{})
		for key, val := range creationInfo {
			switch key {
			case "comment":
				ci.CreatorComment = val.(string)
			case "created":
				ci.Created = val.(string)
			case "licenseListVersion":
				ci.LicenseListVersion = val.(string)
			case "creators":
				err := parseCreators(creationInfo["creators"], ci)
				if err != nil {
					return fmt.Errorf("%s", err)
				}
			}
		}
	case "externalDocumentRefs":
		err := parseExternalDocumentRefs(value, ci)
		if err != nil {
			return fmt.Errorf("%s", err)
		}
	default:
		return fmt.Errorf("unrecognized key %v", key)

	}

	return nil
}

// ===== Helper functions =====

func parseCreators(creators interface{}, ci *spdx.CreationInfo2_2) error {
	if reflect.TypeOf(creators).Kind() == reflect.Slice {
		s := reflect.ValueOf(creators)

		for i := 0; i < s.Len(); i++ {
			subkey, subvalue, err := extractSubs(s.Index(i).Interface().(string))
			if err != nil {
				return err
			}
			switch subkey {
			case "Person":
				ci.CreatorPersons = append(ci.CreatorPersons, subvalue)
			case "Organization":
				ci.CreatorOrganizations = append(ci.CreatorOrganizations, subvalue)
			case "Tool":
				ci.CreatorTools = append(ci.CreatorTools, subvalue)
			default:
				return fmt.Errorf("unrecognized Creator type %v", subkey)
			}

		}
	}
	return nil
}

func parseExternalDocumentRefs(references interface{}, ci *spdx.CreationInfo2_2) error {
	if reflect.TypeOf(references).Kind() == reflect.Slice {
		s := reflect.ValueOf(references)

		for i := 0; i < s.Len(); i++ {
			ref := s.Index(i).Interface().(map[string]interface{})
			documentRefID := ref["externalDocumentId"].(string)
			if !strings.HasPrefix(documentRefID, "DocumentRef-") {
				return fmt.Errorf("expected first element to have DocumentRef- prefix")
			}
			documentRefID = strings.TrimPrefix(documentRefID, "DocumentRef-")
			if documentRefID == "" {
				return fmt.Errorf("document identifier has nothing after prefix")
			}
			checksum := ref["checksum"].(map[string]interface{})
			edr := spdx.ExternalDocumentRef2_2{
				DocumentRefID: documentRefID,
				URI:           ref["spdxDocument"].(string),
				Alg:           checksum["algorithm"].(string),
				Checksum:      checksum["checksumValue"].(string),
			}

			ci.ExternalDocumentReferences[documentRefID] = edr
		}
	}
	return nil
}

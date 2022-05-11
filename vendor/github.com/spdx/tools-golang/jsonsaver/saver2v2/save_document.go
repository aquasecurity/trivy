// Package saver2v2 contains functions to render and write a json
// formatted version of an in-memory SPDX document and its sections
// (version 2.2).
// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
package saver2v2

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/spdx/tools-golang/spdx"
	"github.com/spdx/tools-golang/spdxlib"
)

// RenderDocument2_2 is the main entry point to take an SPDX in-memory
// Document (version 2.2), and render it to the received *bytes.Buffer.
// It is only exported in order to be available to the jsonsaver package,
// and typically does not need to be called by client code.
func RenderDocument2_2(doc *spdx.Document2_2, buf *bytes.Buffer) error {

	jsondocument := make(map[string]interface{})
	// start to parse the creationInfo
	if doc.CreationInfo == nil {
		return fmt.Errorf("document had nil CreationInfo section")
	}
	err := renderCreationInfo2_2(doc.CreationInfo, jsondocument)
	if err != nil {
		return err
	}

	// save otherlicenses from sodx struct to json
	if doc.OtherLicenses != nil {
		_, err = renderOtherLicenses2_2(doc.OtherLicenses, jsondocument)
		if err != nil {
			return err
		}
	}

	// save document level annotations
	if doc.Annotations != nil {
		ann, err := renderAnnotations2_2(doc.Annotations, spdx.MakeDocElementID("", string(doc.CreationInfo.SPDXIdentifier)))
		if err != nil {
			return err
		}

		jsondocument["annotations"] = ann

	}

	// save document describes
	describes, _ := spdxlib.GetDescribedPackageIDs2_2(doc)
	if describes != nil {
		var describesID []string
		for _, v := range describes {
			describesID = append(describesID, spdx.RenderElementID(v))
		}
		jsondocument["documentDescribes"] = describesID
	}
	allfiles := make(map[spdx.ElementID]*spdx.File2_2)
	// save packages from spdx to json
	if doc.Packages != nil {
		_, err = renderPackage2_2(doc, jsondocument, allfiles)
		if err != nil {
			return err
		}
	}

	for k, v := range doc.UnpackagedFiles {
		allfiles[k] = v
	}

	// save files and snippets from spdx to json
	if allfiles != nil {
		_, err = renderFiles2_2(doc, jsondocument, allfiles)
		if err != nil {
			return err
		}
		_, err = renderSnippets2_2(jsondocument, allfiles)
		if err != nil {
			return err
		}

	}

	// save reviews from spdx to json
	if doc.Reviews != nil {
		_, err = renderReviews2_2(doc.Reviews, jsondocument)
		if err != nil {
			return err
		}

	}

	// save relationships  from spdx to json
	if doc.Relationships != nil {
		_, err = renderRelationships2_2(doc.Relationships, jsondocument)
		if err != nil {
			return err
		}

	}

	jsonspec, err := json.MarshalIndent(jsondocument, "", "\t")
	if err != nil {
		return err
	}
	buf.Write(jsonspec)
	return nil
}

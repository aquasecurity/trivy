// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"fmt"
	"io"
	"sort"

	"github.com/spdx/tools-golang/spdx"
)

func renderCreationInfo2_2(ci *spdx.CreationInfo2_2, w io.Writer) error {
	if ci.SPDXVersion != "" {
		fmt.Fprintf(w, "SPDXVersion: %s\n", ci.SPDXVersion)
	}
	if ci.DataLicense != "" {
		fmt.Fprintf(w, "DataLicense: %s\n", ci.DataLicense)
	}
	if ci.SPDXIdentifier != "" {
		fmt.Fprintf(w, "SPDXID: %s\n", spdx.RenderElementID(ci.SPDXIdentifier))
	}
	if ci.DocumentName != "" {
		fmt.Fprintf(w, "DocumentName: %s\n", ci.DocumentName)
	}
	if ci.DocumentNamespace != "" {
		fmt.Fprintf(w, "DocumentNamespace: %s\n", ci.DocumentNamespace)
	}
	// print EDRs in order sorted by identifier
	edrIDs := []string{}
	for docRefID := range ci.ExternalDocumentReferences {
		edrIDs = append(edrIDs, docRefID)
	}
	sort.Strings(edrIDs)
	for _, edrID := range edrIDs {
		edr := ci.ExternalDocumentReferences[edrID]
		fmt.Fprintf(w, "ExternalDocumentRef: DocumentRef-%s %s %s:%s\n",
			edr.DocumentRefID, edr.URI, edr.Alg, edr.Checksum)
	}
	if ci.LicenseListVersion != "" {
		fmt.Fprintf(w, "LicenseListVersion: %s\n", ci.LicenseListVersion)
	}
	for _, s := range ci.CreatorPersons {
		fmt.Fprintf(w, "Creator: Person: %s\n", s)
	}
	for _, s := range ci.CreatorOrganizations {
		fmt.Fprintf(w, "Creator: Organization: %s\n", s)
	}
	for _, s := range ci.CreatorTools {
		fmt.Fprintf(w, "Creator: Tool: %s\n", s)
	}
	if ci.Created != "" {
		fmt.Fprintf(w, "Created: %s\n", ci.Created)
	}
	if ci.CreatorComment != "" {
		fmt.Fprintf(w, "CreatorComment: %s\n", textify(ci.CreatorComment))
	}
	if ci.DocumentComment != "" {
		fmt.Fprintf(w, "DocumentComment: %s\n", textify(ci.DocumentComment))
	}

	// add blank newline b/c end of a main section
	fmt.Fprintf(w, "\n")

	return nil
}

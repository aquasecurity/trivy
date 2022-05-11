// SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later

package saver2v2

import (
	"fmt"
	"io"

	"github.com/spdx/tools-golang/spdx"
)

func renderOtherLicense2_2(ol *spdx.OtherLicense2_2, w io.Writer) error {
	if ol.LicenseIdentifier != "" {
		fmt.Fprintf(w, "LicenseID: %s\n", ol.LicenseIdentifier)
	}
	if ol.ExtractedText != "" {
		fmt.Fprintf(w, "ExtractedText: %s\n", textify(ol.ExtractedText))
	}
	if ol.LicenseName != "" {
		fmt.Fprintf(w, "LicenseName: %s\n", ol.LicenseName)
	}
	for _, s := range ol.LicenseCrossReferences {
		fmt.Fprintf(w, "LicenseCrossReference: %s\n", s)
	}
	if ol.LicenseComment != "" {
		fmt.Fprintf(w, "LicenseComment: %s\n", textify(ol.LicenseComment))
	}

	fmt.Fprintf(w, "\n")

	return nil
}

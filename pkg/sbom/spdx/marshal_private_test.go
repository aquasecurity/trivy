package spdx

import (
	"sort"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/require"
)

func TestMarshaler_normalizeLicenses(t *testing.T) {
	tests := []struct {
		name              string
		input             []string
		wantLicenseName   string
		wantOtherLicenses []*spdx.OtherLicense
	}{
		{
			name: "happy path",
			input: []string{
				"GPLv2+",
			},
			wantLicenseName: "GPL-2.0-or-later",
		},
		{
			name: "happy path with multi license",
			input: []string{
				"GPLv2+",
				"GPLv3+",
			},
			wantLicenseName: "GPL-2.0-or-later AND GPL-3.0-or-later",
		},
		{
			name: "happy path with OR operator",
			input: []string{
				"GPLv2+",
				"LGPL 2.0 or GNU LESSER",
			},
			wantLicenseName: "GPL-2.0-or-later AND (LGPL-2.0-only OR LGPL-2.1-only)",
		},
		{
			name: "happy path with OR operator with non-SPDX license",
			input: []string{
				"GPLv2+",
				"wrong-license or unknown-license",
			},
			wantLicenseName: "GPL-2.0-or-later AND (LicenseRef-3a64a1cb4bc51d5d OR LicenseRef-398e59dafb7d221c)",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-398e59dafb7d221c",
					LicenseName:       "unknown-license",
				},
				{
					LicenseIdentifier: "LicenseRef-3a64a1cb4bc51d5d",
					LicenseName:       "wrong-license",
				},
			},
		},
		{
			name: "happy path with AND operator",
			input: []string{
				"GPLv2+",
				"LGPL 2.0 and GNU LESSER",
			},
			wantLicenseName: "GPL-2.0-or-later AND LGPL-2.0-only AND LGPL-2.1-only",
		},
		{
			name: "happy path with WITH operator",
			input: []string{
				"AFL 2.0",
				"AFL 3.0 with Autoconf-exception-3.0",
			},
			wantLicenseName: "AFL-2.0 AND AFL-3.0 WITH Autoconf-exception-3.0",
		},
		{
			name: "happy path with non-SPDX exception",
			input: []string{
				"AFL 2.0",
				"AFL 3.0 with wrong-exceptions",
			},
			wantLicenseName: "AFL-2.0 AND LicenseRef-64ec018384f0fde7",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-64ec018384f0fde7",
					LicenseName:       "AFL-3.0 WITH wrong-exceptions",
				},
			},
		},
		{
			name: "happy path with text of license",
			input: []string{
				"text://unknown-license",
				"AFL 2.0",
				"unknown-license",
			},
			wantLicenseName: "LicenseRef-d94457d3705e6c77 AND AFL-2.0 AND LicenseRef-398e59dafb7d221c",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-398e59dafb7d221c",
					LicenseName:       "unknown-license",
				},
				{
					LicenseIdentifier: "LicenseRef-d94457d3705e6c77",
					ExtractedText:     "unknown-license",
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			m := NewMarshaler("")
			gotLicenseName, gotOtherLicenses := m.normalizeLicenses(tt.input)
			// We will sort all OtherLicenses for SPDX document
			// So we need to sort OtherLicenses for this test
			sort.Slice(gotOtherLicenses, func(i, j int) bool {
				return gotOtherLicenses[i].LicenseIdentifier < gotOtherLicenses[j].LicenseIdentifier
			})
			require.Equal(t, tt.wantLicenseName, gotLicenseName)
			require.Equal(t, tt.wantOtherLicenses, gotOtherLicenses)
		})
	}
}

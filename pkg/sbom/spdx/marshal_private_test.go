package spdx

import (
	"sort"
	"testing"

	"github.com/spdx/tools-golang/spdx"
	"github.com/stretchr/testify/assert"
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
				"BSD-4-Clause",
			},
			wantLicenseName: "GPL-2.0-or-later AND GPL-3.0-or-later AND BSD-4-Clause",
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
			wantLicenseName: "GPL-2.0-or-later AND (LicenseRef-c581e42fe705aa48 OR LicenseRef-a0bb0951a6dfbdbe)",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-a0bb0951a6dfbdbe",
					LicenseName:       "unknown-license",
					ExtractedText:     `This component is licensed under "unknown-license"`,
				},
				{
					LicenseIdentifier: "LicenseRef-c581e42fe705aa48",
					LicenseName:       "wrong-license",
					ExtractedText:     `This component is licensed under "wrong-license"`,
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
				"GPLv2",
				"AFL 3.0 with wrong-exceptions",
				"LGPL 2.0 and unknown-license and GNU LESSER",
				"AFL 3.0 with Autoconf-exception-3.0",
			},
			wantLicenseName: "GPL-2.0-only AND LicenseRef-51373b28fab165e9 AND LGPL-2.0-only AND LicenseRef-a0bb0951a6dfbdbe AND LGPL-2.1-only AND AFL-3.0 WITH Autoconf-exception-3.0",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-51373b28fab165e9",
					LicenseName:       "AFL-3.0 WITH wrong-exceptions",
					ExtractedText:     `This component is licensed under "AFL-3.0 WITH wrong-exceptions"`,
				},
				{
					LicenseIdentifier: "LicenseRef-a0bb0951a6dfbdbe",
					LicenseName:       "unknown-license",
					ExtractedText:     `This component is licensed under "unknown-license"`,
				},
			},
		},
		{
			name: "happy path with non-SPDX exception",
			input: []string{
				"AFL 2.0",
				"AFL 3.0 with wrong-exceptions",
			},
			wantLicenseName: "AFL-2.0 AND LicenseRef-51373b28fab165e9",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-51373b28fab165e9",
					LicenseName:       "AFL-3.0 WITH wrong-exceptions",
					ExtractedText:     `This component is licensed under "AFL-3.0 WITH wrong-exceptions"`,
				},
			},
		},
		{
			name: "happy path with incorrect cases for license and exception",
			input: []string{
				"afl 3.0 with autoCONF-exception-3.0",
			},
			wantLicenseName: "AFL-3.0 WITH Autoconf-exception-3.0",
		},
		{
			name: "happy path with text of license",
			input: []string{
				"text://Redistribution and use in source and binary forms, with or without",
				"AFL 2.0",
				"unknown-license",
			},
			wantLicenseName: "LicenseRef-b5b4cc09bc5f0e16 AND AFL-2.0 AND LicenseRef-a0bb0951a6dfbdbe",
			wantOtherLicenses: []*spdx.OtherLicense{
				{
					LicenseIdentifier: "LicenseRef-a0bb0951a6dfbdbe",
					LicenseName:       "unknown-license",
					ExtractedText:     `This component is licensed under "unknown-license"`,
				},
				{
					LicenseIdentifier: "LicenseRef-b5b4cc09bc5f0e16",
					LicenseName:       "NOASSERTION",
					ExtractedText:     "Redistribution and use in source and binary forms, with or without",
					LicenseComment:    "The license text represents text found in package metadata and may not represent the full text of the license",
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
			assert.Equal(t, tt.wantLicenseName, gotLicenseName)
			assert.Equal(t, tt.wantOtherLicenses, gotOtherLicenses)
		})
	}
}

package licensing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/licensing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		licenses      []string
		normalized    string
		normalizedKey string
	}{
		{
			[]string{
				"APACHE",
				" APACHE ",
				"APACHE License",
				"ApacheLicense",
				"ApacheLicence",
				"The Apache License",
				"THE APACHE LICENSE",
				"  THE APACHE LICENSE  ",
				"  THE\tAPACHE  \r\nLICENSE  \r\n ",
				"apache-license",
				"apache-licence",
				"apache-licensed",
				"apache-licensed",
			},
			"Apache-2.0",
			"Apache-2.0",
		},
		{
			[]string{
				"Apache+",
			},
			"Apache-2.0+",
			"Apache-2.0",
		},
		{
			[]string{
				"GPL-or-later",
				"GPL+",
				"GPL-2.0-only+",
			},
			"GPL-2.0-or-later",
			"GPL-2.0",
		},
		{
			[]string{
				"GPL (≥ 3)",
				"GPL3+",
				"GPL3-or-later",
				"GPL3 or later licence",
			},
			"GPL-3.0-or-later",
			"GPL-3.0",
		},
		{
			[]string{
				"The Unlicense",
				"Unlicense",
				"Unlicensed",
				"UNLICENSE",
				"UNLICENSED",
			},
			"Unlicense",
			"Unlicense",
		},
		{
			[]string{
				"MIT License",
				"http://json.codeplex.com/license",
			},
			"MIT",
			"MIT",
		},
		{
			[]string{
				" The unmapped license ",
			},
			" The unmapped license ",
			" The unmapped license ",
		},
	}
	for _, tt := range tests {
		t.Run(tt.normalized, func(t *testing.T) {
			for _, ll := range tt.licenses {
				normalized := licensing.Normalize(ll)
				normalizedKey := licensing.NormalizeLicense(ll).License
				assert.Equal(t, tt.normalized, normalized)
				assert.Equal(t, tt.normalizedKey, normalizedKey)
			}
		})
	}
}

func TestSplitLicenses(t *testing.T) {
	tests := []struct {
		name     string
		license  string
		licenses []string
	}{
		{
			"simple list comma-separated",
			"GPL-1+,GPL-2",
			[]string{
				"GPL-1+",
				"GPL-2",
			},
		},
		{
			"simple list comma-separated",
			"GPL-1+,GPL-2,GPL-3",
			[]string{
				"GPL-1+",
				"GPL-2",
				"GPL-3",
			},
		},
		{
			"3 licenses 'or'-separated",
			"GPL-1+ or Artistic or Artistic-dist",
			[]string{
				"GPL-1+",
				"Artistic",
				"Artistic-dist",
			},
		},
		{
			"two licenses _or_ separated",
			"LGPLv3+_or_GPLv2+",
			[]string{
				"LGPLv3+",
				"GPLv2+",
			},
		},
		{
			"licenses `and`-separated",
			"BSD-3-CLAUSE and GPL-2",
			[]string{
				"BSD-3-CLAUSE",
				"GPL-2",
			},
		},
		{
			"three licenses and/or separated",
			"GPL-1+ or Artistic, and BSD-4-clause-POWERDOG",
			[]string{
				"GPL-1+",
				"Artistic",
				"BSD-4-clause-POWERDOG",
			},
		},
		{
			"two licenses with version",
			"Apache License,Version 2.0, OSET Public License version 2.1",
			[]string{
				"Apache License, Version 2.0",
				"OSET Public License version 2.1",
			},
		},
		{
			"the license starts with `ver`",
			"verbatim and BSD-4-clause",
			[]string{
				"verbatim",
				"BSD-4-clause",
			},
		},
		{
			"the license with `or later`",
			"GNU Affero General Public License v3 or later (AGPLv3+)",
			[]string{
				"GNU Affero General Public License v3 or later (AGPLv3+)",
			},
		},
		{
			"Python license exceptions",
			"GNU Library or Lesser General Public License (LGPL), Common Development and Distribution License 1.0 (CDDL-1.0), Historical Permission Notice and Disclaimer (HPND)",
			[]string{
				"GNU Library or Lesser General Public License (LGPL)",
				"Common Development and Distribution License 1.0 (CDDL-1.0)",
				"Historical Permission Notice and Disclaimer (HPND)",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := licensing.SplitLicenses(tt.license)
			assert.Equal(t, tt.licenses, res)
		})
	}
}

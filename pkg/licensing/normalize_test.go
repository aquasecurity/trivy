package licensing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/licensing"
)

func TestMap(t *testing.T) {
	assert.Empty(t, licensing.InvalidMappingKeys((nil)))
}

func TestNormalize(t *testing.T) {
	tests := []struct {
		licenses      []string
		normalized    string
		normalizedKey string
	}{
		{
			[]string{
				"  the apache license  ",
				"  the\tapache  \r\nlicense  \r\n ",
				" apache ",
				"ApacheLicence",
				"ApacheLicense",
				"al-2",
				"al-v2",
				"al2",
				"alv2",
				"apache - v 2.0",
				"apache - version 2.0",
				"apache 2",
				"apache 2.0",
				"apache license (2.0)",
				"apache license (v. 2)",
				"apache license (v. 2.0)",
				"apache license (v2)",
				"apache license (v2.0)",
				"apache license (version 2.0)",
				"apache license 2",
				"apache license 2.0",
				"apache license v2",
				"apache license v2.0",
				"apache license version 2",
				"apache license version 2.0",
				"apache license",
				"apache license, 2.0",
				"apache license, asl version 2.0",
				"apache license, version 2",
				"apache license, version 2.0 (http://www.apache.org/licenses/license-2.0)",
				"apache license, version 2.0",
				"apache license,version 2.0",
				"apache license,version-2.0",
				"apache license-2.0",
				"apache public 2.0",
				"apache public license 2.0",
				"apache public license-2.0",
				"apache public-2",
				"apache public-2.0",
				"apache software license (apache-2.0)",
				"apache software license - version 2.0",
				"apache software license 2.0",
				"apache software license, version 2",
				"apache software license, version 2.0",
				"apache software-2.0",
				"apache v 2.0",
				"apache v2",
				"apache v2.0",
				"apache version 2.0",
				"apache version 2.0, january 2004",
				"apache version-2",
				"apache version-2.0",
				"apache",
				"apache, 2",
				"apache, v2.0",
				"apache, version 2",
				"apache, version 2.0",
				"apache-2",
				"apache-2.0",
				"apache-licence",
				"apache-license",
				"apache-licensed",
				"apache-licensed",
				"asf 2.0",
				"asl 2",
				"asl, version 2",
				"asl2.0",
				"the apache license",
				"the apache license",
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
				"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) V1.1",
				"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) VERSION 1.1",
				"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL), VERSION 1.1",
				"COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.1 (CDDL-1.1)",
			},
			"CDDL-1.1",
			"CDDL-1.1",
		},
		{
			[]string{
				"ECLIPSE PUBLIC LICENSE (EPL) 1.0",
				"ECLIPSE PUBLIC LICENSE (EPL), VERSION 1.0",
				"ECLIPSE PUBLIC LICENSE - V 1.0",
				"ECLIPSE PUBLIC LICENSE - V1.0",
				"ECLIPSE PUBLIC LICENSE - VERSION 1.0",
				"ECLIPSE PUBLIC LICENSE 1.0 (EPL-1.0)",
				"ECLIPSE PUBLIC LICENSE 1.0",
				"ECLIPSE PUBLIC LICENSE V. 1.0",
				"ECLIPSE PUBLIC LICENSE V1.0",
				"ECLIPSE PUBLIC LICENSE VERSION 1.0",
				"ECLIPSE PUBLIC LICENSE, VERSION 1.0",
				"ECLIPSE PUBLIC",
			},
			"EPL-1.0",
			"EPL-1.0",
		},
		{
			[]string{
				"EUROPEAN UNION PUBLIC LICENSE (EUPL V.1.1)",
				"EUROPEAN UNION PUBLIC LICENSE 1.1 (EUPL 1.1)",
				"EUROPEAN UNION PUBLIC LICENSE 1.1",
				"EUROPEAN UNION PUBLIC LICENSE, VERSION 1.1",
			},
			"EUPL-1.1",
			"EUPL-1.1",
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
				"GNU GENERAL PUBLIC LICENSE 3",
				"GNU GENERAL PUBLIC LICENSE (GPL) V. 3",
				"GNU GENERAL PUBLIC LICENSE VERSION 3 (GPL V3)",
			},
			"GPL-3.0-only",
			"GPL-3.0",
		},

		{
			[]string{
				"LGPL LICENSE-3",
				"GNU LESSER GENERAL PUBLIC LICENSE V3",
				"GNU LESSER GENERAL PUBLIC LICENSE V3.0",
				"GNU LESSER GENERAL PUBLIC LICENSE VERSION 3",
				"GNU LESSER GENERAL PUBLIC LICENSE VERSION 3.0",
				"GNU LESSER GENERAL PUBLIC LICENSE, VERSION 3.0",
				"GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE VERSION 3.0 (LGPLV3)",
				"GNU GENERAL LESSER PUBLIC LICENSE (LGPL) VERSION 3.0",
				"GNU LESSER GENERAL PUBLIC LICENSE (LGPL), VERSION 3",
			},
			"LGPL-3.0-only",
			"LGPL-3.0",
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

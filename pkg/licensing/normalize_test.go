package licensing_test

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/licensing"
	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		licenses    []expression.Expression
		want        string
		wantLicense expression.Expression
	}{
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "  the apache license  "},
				expression.SimpleExpr{License: "  the\tapache  \r\nlicense  \r\n "},
				expression.SimpleExpr{License: " apache "},
				expression.SimpleExpr{License: "ApacheLicence"},
				expression.SimpleExpr{License: "ApacheLicense"},
				expression.SimpleExpr{License: "al-2"},
				expression.SimpleExpr{License: "al-v2"},
				expression.SimpleExpr{License: "al2"},
				expression.SimpleExpr{License: "alv2"},
				expression.SimpleExpr{License: "apache - v 2.0"},
				expression.SimpleExpr{License: "apache - v. 2.0"},
				expression.SimpleExpr{License: "apache - ver 2.0"},
				expression.SimpleExpr{License: "apache - version 2.0"},
				expression.SimpleExpr{License: "apache 2"},
				expression.SimpleExpr{License: "apache 2.0"},
				expression.SimpleExpr{License: "apache license (2.0)"},
				expression.SimpleExpr{License: "apache license (v. 2)"},
				expression.SimpleExpr{License: "apache license (v. 2.0)"},
				expression.SimpleExpr{License: "apache license (v2)"},
				expression.SimpleExpr{License: "apache license (v2.0)"},
				expression.SimpleExpr{License: "apache license (version 2.0)"},
				expression.SimpleExpr{License: "apache license 2"},
				expression.SimpleExpr{License: "apache license 2.0"},
				expression.SimpleExpr{License: "apache license v2"},
				expression.SimpleExpr{License: "apache license v2.0"},
				expression.SimpleExpr{License: "apache license version 2"},
				expression.SimpleExpr{License: "apache license version 2.0"},
				expression.SimpleExpr{License: "apache license"},
				expression.SimpleExpr{License: "apache license, 2.0"},
				expression.SimpleExpr{License: "apache license, asl version 2.0"},
				expression.SimpleExpr{License: "apache license, version 2"},
				expression.SimpleExpr{License: "apache license, version 2.0 (http://www.apache.org/licenses/license-2.0)"},
				expression.SimpleExpr{License: "apache license, version 2.0"},
				expression.SimpleExpr{License: "apache license,version 2.0"},
				expression.SimpleExpr{License: "apache license,version-2.0"},
				expression.SimpleExpr{License: "apache license-2.0"},
				expression.SimpleExpr{License: "apache public 2.0"},
				expression.SimpleExpr{License: "apache public license 2.0"},
				expression.SimpleExpr{License: "apache public license-2.0"},
				expression.SimpleExpr{License: "apache public-2"},
				expression.SimpleExpr{License: "apache public-2.0"},
				expression.SimpleExpr{License: "apache software license (apache-2.0)"},
				expression.SimpleExpr{License: "apache software license - version 2.0"},
				expression.SimpleExpr{License: "apache software license 2.0"},
				expression.SimpleExpr{License: "apache software license, version 2"},
				expression.SimpleExpr{License: "apache software license, version 2.0"},
				expression.SimpleExpr{License: "apache software-2.0"},
				expression.SimpleExpr{License: "apache v 2.0"},
				expression.SimpleExpr{License: "apache v. 2.0"},
				expression.SimpleExpr{License: "apache v2"},
				expression.SimpleExpr{License: "apache v2.0"},
				expression.SimpleExpr{License: "apache ver 2.0"},
				expression.SimpleExpr{License: "apache ver. 2.0"},
				expression.SimpleExpr{License: "apache version 2.0"},
				expression.SimpleExpr{License: "apache version 2.0, january 2004"},
				expression.SimpleExpr{License: "apache version-2"},
				expression.SimpleExpr{License: "apache version-2.0"},
				expression.SimpleExpr{License: "apache"},
				expression.SimpleExpr{License: "apache, 2"},
				expression.SimpleExpr{License: "apache, v2.0"},
				expression.SimpleExpr{License: "apache, version 2"},
				expression.SimpleExpr{License: "apache, version 2.0"},
				expression.SimpleExpr{License: "apache-2"},
				expression.SimpleExpr{License: "apache-2.0"},
				expression.SimpleExpr{License: "apache-licence"},
				expression.SimpleExpr{License: "apache-license"},
				expression.SimpleExpr{License: "apache-licensed"},
				expression.SimpleExpr{License: "apache-licensed"},
				expression.SimpleExpr{License: "asf 2.0"},
				expression.SimpleExpr{License: "asl 2"},
				expression.SimpleExpr{License: "asl, version 2"},
				expression.SimpleExpr{License: "asl2.0"},
				expression.SimpleExpr{License: "the apache license"},
				expression.SimpleExpr{License: "the apache license"},
			},
			want:        "Apache-2.0",
			wantLicense: expression.SimpleExpr{License: "Apache-2.0"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "Apache+"},
			},
			want:        "Apache-2.0+",
			wantLicense: expression.SimpleExpr{License: "Apache-2.0", HasPlus: true},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) V1.1"},
				expression.SimpleExpr{License: "COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL) VERSION 1.1"},
				expression.SimpleExpr{License: "COMMON DEVELOPMENT AND DISTRIBUTION LICENSE (CDDL), VERSION 1.1"},
				expression.SimpleExpr{License: "COMMON DEVELOPMENT AND DISTRIBUTION LICENSE 1.1 (CDDL-1.1)"},
			},
			want:        "CDDL-1.1",
			wantLicense: expression.SimpleExpr{License: "CDDL-1.1"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE (EPL) 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE (EPL), VERSION 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE - V 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE - V1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE - VERSION 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE 1.0 (EPL-1.0)"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE V. 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE V1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE VERSION 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC LICENSE, VERSION 1.0"},
				expression.SimpleExpr{License: "ECLIPSE PUBLIC"},
			},
			want:        "EPL-1.0",
			wantLicense: expression.SimpleExpr{License: "EPL-1.0"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "EUROPEAN UNION PUBLIC LICENSE (EUPL V.1.1)"},
				expression.SimpleExpr{License: "EUROPEAN UNION PUBLIC LICENSE 1.1 (EUPL 1.1)"},
				expression.SimpleExpr{License: "EUROPEAN UNION PUBLIC LICENSE 1.1"},
				expression.SimpleExpr{License: "EUROPEAN UNION PUBLIC LICENSE, VERSION 1.1"},
			},
			want:        "EUPL-1.1",
			wantLicense: expression.SimpleExpr{License: "EUPL-1.1"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "GPL-or-later"},
				expression.SimpleExpr{License: "GPL+"},
				expression.SimpleExpr{License: "GPL-2.0-only+"},
			},
			want:        "GPL-2.0-or-later",
			wantLicense: expression.SimpleExpr{License: "GPL-2.0", HasPlus: true},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "GPL (≥ 3)"},
				expression.SimpleExpr{License: "GPL3+"},
				expression.SimpleExpr{License: "GPL3-or-later"},
				expression.SimpleExpr{License: "GPL3 or later licence"},
			},
			want:        "GPL-3.0-or-later",
			wantLicense: expression.SimpleExpr{License: "GPL-3.0", HasPlus: true},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "GNU GENERAL PUBLIC LICENSE 3"},
				expression.SimpleExpr{License: "GNU GENERAL PUBLIC LICENSE (GPL) V. 3"},
				expression.SimpleExpr{License: "GNU GENERAL PUBLIC LICENSE VERSION 3 (GPL V3)"},
			},
			want:        "GPL-3.0-only",
			wantLicense: expression.SimpleExpr{License: "GPL-3.0"},
		},

		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "LGPL LICENSE-3"},
				expression.SimpleExpr{License: "GNU LESSER GENERAL PUBLIC LICENSE V3"},
				expression.SimpleExpr{License: "GNU LESSER GENERAL PUBLIC LICENSE V3.0"},
				expression.SimpleExpr{License: "GNU LESSER GENERAL PUBLIC LICENSE VERSION 3"},
				expression.SimpleExpr{License: "GNU LESSER GENERAL PUBLIC LICENSE VERSION 3.0"},
				expression.SimpleExpr{License: "GNU LESSER GENERAL PUBLIC LICENSE, VERSION 3.0"},
				expression.SimpleExpr{License: "GNU LIBRARY OR LESSER GENERAL PUBLIC LICENSE VERSION 3.0 (LGPLV3)"},
				expression.SimpleExpr{License: "GNU GENERAL LESSER PUBLIC LICENSE (LGPL) VERSION 3.0"},
				expression.SimpleExpr{License: "GNU LESSER GENERAL PUBLIC LICENSE (LGPL), VERSION 3"},
			},
			want:        "LGPL-3.0-only",
			wantLicense: expression.SimpleExpr{License: "LGPL-3.0"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "The Unlicense"},
				expression.SimpleExpr{License: "Unlicense"},
				expression.SimpleExpr{License: "Unlicensed"},
				expression.SimpleExpr{License: "UNLICENSE"},
				expression.SimpleExpr{License: "UNLICENSED"},
			},
			want:        "Unlicense",
			wantLicense: expression.SimpleExpr{License: "Unlicense"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "MIT License"},
				expression.SimpleExpr{License: "http://json.codeplex.com/license"},
			},
			want:        "MIT",
			wantLicense: expression.SimpleExpr{License: "MIT"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: " The unmapped license "},
			},
			want:        "The unmapped license",
			wantLicense: expression.SimpleExpr{License: "The unmapped license"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "Universal Permissive License, Version 1.0"},
			},
			want:        "UPL-1.0",
			wantLicense: expression.SimpleExpr{License: "UPL-1.0"},
		},
		{
			licenses: []expression.Expression{
				expression.SimpleExpr{License: "GPLv2 WITH EXCEPTIONS"},
				expression.NewCompoundExpr( // "GPLv2 WITH EXCEPTIONS"
					expression.SimpleExpr{License: "GPLv2"},
					expression.TokenWith,
					expression.SimpleExpr{License: "EXCEPTIONS"},
				),
			},
			want:        "GPL-2.0-with-classpath-exception",
			wantLicense: expression.SimpleExpr{License: "GPL-2.0-with-classpath-exception"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			for _, ll := range tt.licenses {
				got := licensing.Normalize(ll.String())
				gotLicense := licensing.NormalizeLicense(ll)
				assert.Equal(t, tt.want, got)
				assert.Equal(t, tt.wantLicense, gotLicense)
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
		{
			name:    "License text",
			license: "* Permission to use this software in any way is granted without",
			licenses: []string{
				"text://* Permission to use this software in any way is granted without",
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

func TestLaxSplitLicense(t *testing.T) {
	var tests = []struct {
		license      string
		wantLicenses []string
	}{
		{
			license:      "ASL 2.0",
			wantLicenses: []string{"Apache-2.0"},
		},
		{
			license: "MPL 2.0 GPL2+",
			wantLicenses: []string{
				"MPL-2.0",
				"GPL-2.0-or-later",
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.license, func(t *testing.T) {
			parsed := licensing.LaxSplitLicenses(tt.license)
			assert.Equal(t, tt.wantLicenses, parsed)
		})
	}
}

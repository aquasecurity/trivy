package licensing

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/trivy/pkg/licensing/expression"
)

// All map keys must be standardized to be matched
// (uppercase, no common suffixes, standardized version, etc.)
func TestMap(t *testing.T) {
	for key := range mapping {
		t.Run(key, func(t *testing.T) {
			standardized := standardizeKeyAndSuffix(key)
			assert.Equal(t, standardized.License, key)
		})
	}
}

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
				expression.SimpleExpr{License: "UNLICENSE"},
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
				got := normalizeLicense(ll.String())
				gotLicense := NormalizeLicenseExpression(ll)
				assert.Equal(t, tt.want, got)
				assert.Equal(t, tt.wantLicense, gotLicense)
			}
		})
	}
}

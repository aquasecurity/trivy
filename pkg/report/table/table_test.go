package table_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func TestReportWriter_Table(t *testing.T) {
	testCases := []struct {
		name               string
		results            types.Results
		expectedOutput     string
		includeNonFailures bool
	}{
		{
			name: "happy path full",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
			expectedOutput: `
test ()
=======
Total: 1 (MEDIUM: 0, HIGH: 1)

┌─────────┬───────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
│ Library │ Vulnerability │ Severity │ Installed Version │ Fixed Version │                   Title                   │
├─────────┼───────────────┼──────────┼───────────────────┼───────────────┼───────────────────────────────────────────┤
│ foo     │ CVE-2020-0001 │ HIGH     │ 1.2.3             │ 3.4.5         │ foobar                                    │
│         │               │          │                   │               │ https://avd.aquasec.com/nvd/cve-2020-0001 │
└─────────┴───────────────┴──────────┴───────────────────┴───────────────┴───────────────────────────────────────────┘
`,
		},
		{
			name: "happy path with filePath in result",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							PkgPath:          "foo/bar",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
			expectedOutput: `
test ()
=======
Total: 1 (MEDIUM: 0, HIGH: 1)

┌───────────┬───────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
│  Library  │ Vulnerability │ Severity │ Installed Version │ Fixed Version │                   Title                   │
├───────────┼───────────────┼──────────┼───────────────────┼───────────────┼───────────────────────────────────────────┤
│ foo (bar) │ CVE-2020-0001 │ HIGH     │ 1.2.3             │ 3.4.5         │ foobar                                    │
│           │               │          │                   │               │ https://avd.aquasec.com/nvd/cve-2020-0001 │
└───────────┴───────────────┴──────────┴───────────────────┴───────────────┴───────────────────────────────────────────┘
`,
		},
		{
			name: "no title for vuln and missing primary link",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							Vulnerability: dbTypes.Vulnerability{
								Description: "foobar",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
			expectedOutput: `
test ()
=======
Total: 1 (MEDIUM: 0, HIGH: 1)

┌─────────┬───────────────┬──────────┬───────────────────┬───────────────┬────────┐
│ Library │ Vulnerability │ Severity │ Installed Version │ Fixed Version │ Title  │
├─────────┼───────────────┼──────────┼───────────────────┼───────────────┼────────┤
│ foo     │ CVE-2020-0001 │ HIGH     │ 1.2.3             │ 3.4.5         │ foobar │
└─────────┴───────────────┴──────────┴───────────────────┴───────────────┴────────┘
`,
		},
		{
			name: "long title for vuln",
			results: types.Results{
				{
					Target: "test",
					Class:  types.ClassLangPkg,
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-1234",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-1234",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "a b c d e f g h i j k l m n o p q r s t u v",
								Description: "foobar",
								Severity:    "HIGH",
							},
						},
					},
				},
			},
			expectedOutput: `
test ()
=======
Total: 1 (MEDIUM: 0, HIGH: 1)

┌─────────┬───────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
│ Library │ Vulnerability │ Severity │ Installed Version │ Fixed Version │                   Title                   │
├─────────┼───────────────┼──────────┼───────────────────┼───────────────┼───────────────────────────────────────────┤
│ foo     │ CVE-2020-1234 │ HIGH     │ 1.2.3             │ 3.4.5         │ a b c d e f g h i j k l...                │
│         │               │          │                   │               │ https://avd.aquasec.com/nvd/cve-2020-1234 │
└─────────┴───────────────┴──────────┴───────────────────┴───────────────┴───────────────────────────────────────────┘
`,
		},
		{
			name:           "no vulns",
			expectedOutput: ``,
		},
		{
			name: "happy path with vulnerability origin graph",
			results: types.Results{
				{
					Target: "package-lock.json",
					Class:  types.ClassLangPkg,
					Type:   "npm",
					Packages: []ftypes.Package{
						{
							ID:      "node-fetch@1.7.3",
							Name:    "node-fetch",
							Version: "1.7.3",
						},
						{
							ID:      "isomorphic-fetch@2.2.1",
							Name:    "isomorphic-fetch",
							Version: "2.2.1",
							DependsOn: []string{
								"node-fetch@1.7.3",
							},
						},
						{
							ID:      "fbjs@0.8.18",
							Name:    "fbjs",
							Version: "0.8.18",
							DependsOn: []string{
								"isomorphic-fetch@2.2.1",
							},
						},
						{
							ID:      "styled-components@3.1.3",
							Name:    "styled-components",
							Version: "3.1.3",
							DependsOn: []string{
								"fbjs@0.8.18",
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2022-0235",
							PkgID:           "node-fetch@1.7.3",
							PkgName:         "node-fetch",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
							},
							InstalledVersion: "1.7.3",
							FixedVersion:     "2.6.7, 3.1.1",
						},
						{
							VulnerabilityID: "CVE-2021-26539",
							PkgID:           "sanitize-html@1.20.0",
							PkgName:         "sanitize-html",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "MEDIUM",
							},
							InstalledVersion: "1.20.0",
							FixedVersion:     "2.3.1",
						},
					},
				},
			},
			expectedOutput: `
package-lock.json (npm)
=======================
Total: 2 (MEDIUM: 1, HIGH: 1)

┌───────────────┬────────────────┬──────────┬───────────────────┬───────────────┬────────┐
│    Library    │ Vulnerability  │ Severity │ Installed Version │ Fixed Version │ Title  │
├───────────────┼────────────────┼──────────┼───────────────────┼───────────────┼────────┤
│ node-fetch    │ CVE-2022-0235  │ HIGH     │ 1.7.3             │ 2.6.7, 3.1.1  │ foobar │
├───────────────┼────────────────┼──────────┼───────────────────┼───────────────┤        │
│ sanitize-html │ CVE-2021-26539 │ MEDIUM   │ 1.20.0            │ 2.3.1         │        │
└───────────────┴────────────────┴──────────┴───────────────────┴───────────────┴────────┘

Dependency Origin Tree (Reversed)
=================================
package-lock.json
├── node-fetch@1.7.3, (MEDIUM: 0, HIGH: 1)
│   └── isomorphic-fetch@2.2.1
│       └── fbjs@0.8.18
│           └── styled-components@3.1.3
└── sanitize-html@1.20.0, (MEDIUM: 1, HIGH: 0)
`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tableWritten := bytes.Buffer{}
			err := report.Write(types.Report{Results: tc.results}, report.Option{
				Format:             report.FormatTable,
				Output:             &tableWritten,
				Tree:               true,
				IncludeNonFailures: tc.includeNonFailures,
				Severities:         []dbTypes.Severity{dbTypes.SeverityHigh, dbTypes.SeverityMedium},
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

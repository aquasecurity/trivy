package report_test

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
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
			expectedOutput: `┌─────────┬───────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
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
			expectedOutput: `┌───────────┬───────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
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
			expectedOutput: `┌─────────┬───────────────┬──────────┬───────────────────┬───────────────┬────────┐
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
			expectedOutput: `┌─────────┬───────────────┬──────────┬───────────────────┬───────────────┬───────────────────────────────────────────┐
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tableWritten := bytes.Buffer{}
			err := report.Write(types.Report{Results: tc.results}, report.Option{
				Format:             "table",
				Output:             &tableWritten,
				IncludeNonFailures: tc.includeNonFailures,
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

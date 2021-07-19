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
		results            report.Results
		expectedOutput     string
		light              bool
		includeNonFailures bool
	}{
		{
			name: "happy path full",
			results: report.Results{
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
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                TITLE                 |
+---------+------------------+----------+-------------------+---------------+--------------------------------------+
| foo     | CVE-2020-0001    | HIGH     | 1.2.3             | 3.4.5         | foobar                               |
|         |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-0001 |
+---------+------------------+----------+-------------------+---------------+--------------------------------------+
`,
		},
		{
			name:  "happy path light",
			light: true,
			results: report.Results{
				{
					Target: "test",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							Vulnerability: dbTypes.Vulnerability{
								Title:    "foobar",
								Severity: "HIGH",
							},
						},
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |
+---------+------------------+----------+-------------------+---------------+
| foo     | CVE-2020-0001    | HIGH     | 1.2.3             | 3.4.5         |
+---------+------------------+----------+-------------------+---------------+
`,
		},
		{
			name: "no title for vuln and missing primary link",
			results: report.Results{
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
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION | TITLE  |
+---------+------------------+----------+-------------------+---------------+--------+
| foo     | CVE-2020-0001    | HIGH     | 1.2.3             | 3.4.5         | foobar |
+---------+------------------+----------+-------------------+---------------+--------+
`,
		},
		{
			name: "long title for vuln",
			results: report.Results{
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
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                TITLE                 |
+---------+------------------+----------+-------------------+---------------+--------------------------------------+
| foo     | CVE-2020-1234    | HIGH     | 1.2.3             | 3.4.5         | a b c d e f g h i j k l...           |
|         |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-1234 |
+---------+------------------+----------+-------------------+---------------+--------------------------------------+
`,
		},
		{
			name: "happy path misconfigurations",
			results: report.Results{
				{
					Target: "test",
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:       "Kubernetes Security Check",
							ID:         "KSV001",
							Title:      "Image tag ':latest' used",
							Message:    "Message",
							Severity:   "HIGH",
							PrimaryURL: "https://avd.aquasec.com/appshield/ksv001",
							Status:     types.StatusFailure,
						},
						{
							Type:       "Kubernetes Security Check",
							ID:         "KSV002",
							Title:      "SYS_ADMIN capability added",
							Message:    "Message",
							Severity:   "CRITICAL",
							PrimaryURL: "https://avd.aquasec.com/appshield/ksv002",
							Status:     types.StatusFailure,
						},
					},
				},
			},
			expectedOutput: `+---------------------------+------------+----------------------------+----------+------------------------------------------+
|           TYPE            | MISCONF ID |           CHECK            | SEVERITY |                 MESSAGE                  |
+---------------------------+------------+----------------------------+----------+------------------------------------------+
| Kubernetes Security Check |   KSV001   | Image tag ':latest' used   |   HIGH   | Message                                  |
|                           |            |                            |          | -->avd.aquasec.com/appshield/ksv001      |
+                           +------------+----------------------------+----------+------------------------------------------+
|                           |   KSV002   | SYS_ADMIN capability added | CRITICAL | Message                                  |
|                           |            |                            |          | -->avd.aquasec.com/appshield/ksv002      |
+---------------------------+------------+----------------------------+----------+------------------------------------------+
`,
		},
		{
			name:               "happy path misconfigurations with successes",
			includeNonFailures: true,
			results: report.Results{
				{
					Target: "test",
					Misconfigurations: []types.DetectedMisconfiguration{
						{
							Type:       "Kubernetes Security Check",
							ID:         "KSV001",
							Title:      "Image tag ':latest' used",
							Message:    "Message",
							Severity:   "HIGH",
							PrimaryURL: "https://avd.aquasec.com/appshield/ksv001",
							Status:     types.StatusFailure,
						},
						{
							Type:       "Kubernetes Security Check",
							ID:         "KSV002",
							Title:      "SYS_ADMIN capability added",
							Message:    "Message",
							Severity:   "CRITICAL",
							PrimaryURL: "https://avd.aquasec.com/appshield/ksv002",
							Status:     types.StatusPassed,
						},
					},
				},
			},
			expectedOutput: `+---------------------------+------------+----------------------------+----------+--------+------------------------------------------+
|           TYPE            | MISCONF ID |           CHECK            | SEVERITY | STATUS |                 MESSAGE                  |
+---------------------------+------------+----------------------------+----------+--------+------------------------------------------+
| Kubernetes Security Check |   KSV001   | Image tag ':latest' used   |   HIGH   |  FAIL  | Message                                  |
|                           |            |                            |          |        | -->avd.aquasec.com/appshield/ksv001      |
+                           +------------+----------------------------+----------+--------+------------------------------------------+
|                           |   KSV002   | SYS_ADMIN capability added | CRITICAL |  PASS  | Message                                  |
+---------------------------+------------+----------------------------+----------+--------+------------------------------------------+
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
			err := report.Write(report.Report{Results: tc.results}, report.Option{
				Format:             "table",
				Output:             &tableWritten,
				Light:              tc.light,
				IncludeNonFailures: tc.includeNonFailures,
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

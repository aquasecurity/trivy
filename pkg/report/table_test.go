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
		name           string
		detectedVulns  []types.DetectedVulnerability
		expectedOutput string
		light          bool
	}{
		{
			name: "happy path full",
			detectedVulns: []types.DetectedVulnerability{
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
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foobar",
						Description: "baz",
						Severity:    "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |
+---------+------------------+----------+-------------------+---------------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         |
+---------+------------------+----------+-------------------+---------------+
`,
		},
		{
			name: "no title for vuln and missing primary link",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Description: "foobar",
						Severity:    "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION | TITLE  |
+---------+------------------+----------+-------------------+---------------+--------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         | foobar |
+---------+------------------+----------+-------------------+---------------+--------+
`,
		},
		{
			name: "long title for vuln",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-2020-1234",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "a b c d e f g h i j k l m n o p q r s t u v",
						Severity: "HIGH",
					},
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------------------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |                TITLE                 |
+---------+------------------+----------+-------------------+---------------+--------------------------------------+
| foo     | CVE-2020-1234    | HIGH     | 1.2.3             | 3.4.5         | a b c d e f g h i j k l...           |
|         |                  |          |                   |               | -->avd.aquasec.com/nvd/cve-2020-0001 |
+---------+------------------+----------+-------------------+---------------+--------------------------------------+
`,
		},
		{
			name:           "no vulns",
			detectedVulns:  []types.DetectedVulnerability{},
			expectedOutput: ``,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputResults := report.Results{
				{
					Target:          "foo",
					Vulnerabilities: tc.detectedVulns,
				},
			}
			tableWritten := bytes.Buffer{}
			assert.NoError(t, report.WriteResults("table", &tableWritten, nil, inputResults, "", tc.light), tc.name)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

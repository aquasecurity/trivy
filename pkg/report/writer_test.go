package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"text/template"

	"github.com/aquasecurity/trivy/pkg/vulnerability"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/stretchr/testify/assert"
)

func TestReportWriter_Table(t *testing.T) {
	testCases := []struct {
		name           string
		detectedVulns  []vulnerability.DetectedVulnerability
		expectedOutput string
	}{
		{
			name: "happy path",
			detectedVulns: []vulnerability.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Title:            "foobar",
					Description:      "baz",
					Severity:         "HIGH",
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
			name: "no title for vuln",
			detectedVulns: []vulnerability.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Description:      "foobar",
					Severity:         "HIGH",
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
			detectedVulns: []vulnerability.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Title:            "a b c d e f g h i j k l m n o p q r s t u v",
					Severity:         "HIGH",
				},
			},
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+----------------------------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION |           TITLE            |
+---------+------------------+----------+-------------------+---------------+----------------------------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         | a b c d e f g h i j k l... |
+---------+------------------+----------+-------------------+---------------+----------------------------+
`,
		},
		{
			name:           "no vulns",
			detectedVulns:  []vulnerability.DetectedVulnerability{},
			expectedOutput: ``,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tw := report.TableWriter{}
			inputResults := report.Results{
				{
					FileName:        "foo",
					Vulnerabilities: tc.detectedVulns,
				},
			}
			tableWritten := bytes.Buffer{}
			tw.Output = &tableWritten
			assert.Nil(t, tw.Write(inputResults))
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

func TestReportWriter_JSON(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []vulnerability.DetectedVulnerability
		expectedJSON  report.Results
	}{
		{
			name: "happy path",
			detectedVulns: []vulnerability.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Title:            "foobar",
					Description:      "baz",
					Severity:         "HIGH",
				},
			},
			expectedJSON: report.Results{
				report.Result{
					FileName: "foojson",
					Vulnerabilities: []vulnerability.DetectedVulnerability{
						{
							VulnerabilityID: "123", PkgName: "foo", InstalledVersion: "1.2.3", FixedVersion: "3.4.5", Title: "foobar", Description: "baz", Severity: "HIGH",
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			jw := report.JsonWriter{}
			jsonWritten := bytes.Buffer{}
			jw.Output = &jsonWritten

			err := jw.Write(report.Results{
				{
					FileName:        "foojson",
					Vulnerabilities: tc.detectedVulns,
				},
			})

			writtenResults := report.Results{}
			errJson := json.Unmarshal([]byte(jsonWritten.String()), &writtenResults)
			assert.NoError(t, errJson, "invalid json written", tc.name)

			assert.Equal(t, tc.expectedJSON, writtenResults, tc.name)
			assert.NoError(t, err, tc.name)
		})
	}

}

func TestReportWriter_Template(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []vulnerability.DetectedVulnerability
		template      string
		expected      string
	}{
		{
			name: "happy path",
			detectedVulns: []vulnerability.DetectedVulnerability{
				{VulnerabilityID: "CVE-2019-0000", PkgName: "foo", Severity: vulnerability.SeverityHigh.String()},
				{VulnerabilityID: "CVE-2019-0000", PkgName: "bar", Severity: vulnerability.SeverityHigh.String()},
				{VulnerabilityID: "CVE-2019-0001", PkgName: "baz", Severity: vulnerability.SeverityCritical.String()},
			},
			template: "{{ range . }}{{ range .Vulnerabilities}}{{ println .VulnerabilityID .Severity }}{{ end }}{{ end }}",
			expected: "CVE-2019-0000 HIGH\nCVE-2019-0000 HIGH\nCVE-2019-0001 CRITICAL\n",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmplWritten := bytes.Buffer{}
			tmpl, _ := template.New(tc.name).Parse(tc.template)
			tmplw := report.TemplateWriter{
				Output:   &tmplWritten,
				Template: tmpl,
			}

			err := tmplw.Write(report.Results{
				{
					FileName:        "foojson",
					Vulnerabilities: tc.detectedVulns,
				},
			})
			assert.NoError(t, err)
			assert.Equal(t, tc.expected, tmplWritten.String())
		})
	}
}

package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/aquasecurity/trivy/pkg/vulnsrc/vulnerability"

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
	}
}

func TestReportWriter_JSON(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []vulnerability.DetectedVulnerability
		expectedJSON  report.Results
		expectedError string
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
		switch {
		case tc.expectedError != "":
			assert.Equal(t, tc.expectedError, err, tc.name)
		default:
			assert.NoError(t, err, tc.name)
		}
	}

}

package report_test

import (
	"bytes"
	"encoding/json"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

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

func TestReportWriter_JSON(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		expectedJSON  report.Results
	}{
		{
			name: "happy path",
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
			expectedJSON: report.Results{
				report.Result{
					Target: "foojson",
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
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			jw := report.JSONWriter{}
			jsonWritten := bytes.Buffer{}
			jw.Output = &jsonWritten

			inputResults := report.Results{
				{
					Target:          "foojson",
					Vulnerabilities: tc.detectedVulns,
				},
			}

			assert.NoError(t, report.WriteResults("json", &jsonWritten, nil, inputResults, "", false), tc.name)

			writtenResults := report.Results{}
			errJson := json.Unmarshal([]byte(jsonWritten.String()), &writtenResults)
			assert.NoError(t, errJson, "invalid json written", tc.name)

			assert.Equal(t, tc.expectedJSON, writtenResults, tc.name)
		})
	}

}

func TestReportWriter_Template(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		template      string
		expected      string
	}{
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "foo",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String()},
				},
				{
					VulnerabilityID: "CVE-2019-0001",
					PkgName:         "baz",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityCritical.String(),
					},
				},
			},
			template: "{{ range . }}{{ range .Vulnerabilities}}{{ println .VulnerabilityID .Severity }}{{ end }}{{ end }}",
			expected: "CVE-2019-0000 HIGH\nCVE-2019-0000 HIGH\nCVE-2019-0001 CRITICAL\n",
		},
		{
			name: "happy path",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "123",
					PkgName:          `foo \ test`,
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       `gcc: POWER9 "DARN" RNG intrinsic produces repeated output`,
						Description: `curl version curl \X 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl < 7.20.0 and curl >= 7.60.0.`,
						Severity:    "HIGH",
					},
				},
			},
			template: `<testsuites>
{{- range . -}}
{{- $failures := len .Vulnerabilities }}
    <testsuite tests="{{ $failures }}" failures="{{ $failures }}" name="{{  .Target }}" errors="0" skipped="0" time="">
	{{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
        <testcase classname="{{ .PkgName }}-{{ .InstalledVersion }}" name="[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}" time="">
            <failure message="{{ escapeXML .Title }}" type="description">{{ escapeXML .Description }}</failure>
        </testcase>
    {{- end }}
	</testsuite>
{{- end }}
</testsuites>`,

			expected: `<testsuites>
    <testsuite tests="1" failures="1" name="foojunit" errors="0" skipped="0" time="">
        <properties>
            <property name="type" value="test"></property>
        </properties>
        <testcase classname="foo \ test-1.2.3" name="[HIGH] 123" time="">
            <failure message="gcc: POWER9 &#34;DARN&#34; RNG intrinsic produces repeated output" type="description">curl version curl \X 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl &lt; 7.20.0 and curl &gt;= 7.60.0.</failure>
        </testcase>
	</testsuite>
</testsuites>`,
		},
		{
			name: "happy path with/without period description should return with period",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "foo",
					Vulnerability: dbTypes.Vulnerability{
						Description: "without period",
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Description: "with period.",
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Description: `with period and unescaped string curl: Use-after-free when closing 'easy' handle in Curl_close().`,
					},
				},
			},
			template: `{{ range . }}{{ range .Vulnerabilities}}{{.VulnerabilityID}} {{ endWithPeriod (escapeString .Description) | printf "%q" }}{{ end }}{{ end }}`,
			expected: `CVE-2019-0000 "without period."CVE-2019-0000 "with period."CVE-2019-0000 "with period and unescaped string curl: Use-after-free when closing &#39;easy&#39; handle in Curl_close()."`,
		},
		{
			name: "Calculate using sprig",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "foo",
					Vulnerability: dbTypes.Vulnerability{
						Description: "without period",
						Severity:    dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Description: "with period.",
						Severity:    dbTypes.SeverityCritical.String(),
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Description: `with period and unescaped string curl: Use-after-free when closing 'easy' handle in Curl_close().`,
						Severity:    dbTypes.SeverityHigh.String(),
					},
				},
			},
			template: `{{ $high := 0 }}{{ $critical := 0 }}{{ range . }}{{ range .Vulnerabilities}}{{ if eq .Severity "HIGH" }}{{ $high = add $high 1 }}{{ end }}{{ if eq .Severity "CRITICAL" }}{{ $critical = add $critical 1 }}{{ end }}{{ end }}Critical: {{ $critical }}, High: {{ $high }}{{ end }}`,
			expected: `Critical: 2, High: 1`,
		},
		{
			name:          "happy path: env var parsing and getCurrentTime",
			detectedVulns: []types.DetectedVulnerability{},
			template:      `{{ toLower (getEnv "AWS_ACCOUNT_ID") }} {{ getCurrentTime }}`,
			expected:      `123456789012 2020-08-10T07:28:17.000958601Z`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report.Now = func() time.Time {
				return time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC)
			}
			os.Setenv("AWS_ACCOUNT_ID", "123456789012")
			tmplWritten := bytes.Buffer{}
			inputResults := report.Results{
				{
					Target:          "foojunit",
					Type:            "test",
					Vulnerabilities: tc.detectedVulns,
				},
			}

			assert.NoError(t, report.WriteResults("template", &tmplWritten, nil, inputResults, tc.template, false))
			assert.Equal(t, tc.expected, tmplWritten.String())
		})
	}
}

func TestReportWriter_Template_SARIF(t *testing.T) {
	testCases := []struct {
		name          string
		detectedVulns []types.DetectedVulnerability
		want          string
	}{
		{
			name: "no primary url",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-1234-5678",
					PkgName:          "foopackage",
					InstalledVersion: "1.2.3",
					FixedVersion:     "4.5.6",
					SeveritySource:   "NVD",
					PrimaryURL:       "",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foovuln",
						Description: "foodesc",
						Severity:    "CRITICAL",
					},
				},
			},
			want: `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "informationUri": "https://github.com/aquasecurity/trivy",
          "fullName": "Trivy Vulnerability Scanner",
          "version": "v0.15.0",
          "rules": [
            {
              "id": "[CRITICAL] CVE-1234-5678 foopackage",
              "name": "dockerfile_scan",
              "shortDescription": {
                "text": "CVE-1234-5678 Package: foopackage"
              },
              "fullDescription": {
                "text": "foovuln."
              },
              "help": {
                "text": "Vulnerability CVE-1234-5678\nSeverity: CRITICAL\nPackage: foopackage\nInstalled Version: 1.2.3\nFixed Version: 4.5.6\nLink: [CVE-1234-5678]()",
                "markdown": "**Vulnerability CVE-1234-5678**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|CRITICAL|foopackage|1.2.3|4.5.6|[CVE-1234-5678]()|\n"
              },
              "properties": {
                "tags": [
                  "vulnerability",
                  "CRITICAL",
                  "foopackage"
                ],
                "precision": "very-high"
              }
            }]
        }
      },
      "results": [
        {
          "ruleId": "[CRITICAL] CVE-1234-5678 foopackage",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "foodesc."
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "Dockerfile"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        }],
      "columnKind": "utf16CodeUnits"
    }
  ]
}`,
		},
		{
			name: "with primary url",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID:  "CVE-1234-5678",
					PkgName:          "foopackage",
					InstalledVersion: "1.2.3",
					FixedVersion:     "4.5.6",
					SeveritySource:   "NVD",
					PrimaryURL:       "https://avd.aquasec.com/nvd/cve-1234-5678",
					Vulnerability: dbTypes.Vulnerability{
						Title:       "foovuln",
						Description: "foodesc",
						Severity:    "CRITICAL",
					},
				},
			},
			want: `{
  "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "informationUri": "https://github.com/aquasecurity/trivy",
          "fullName": "Trivy Vulnerability Scanner",
          "version": "v0.15.0",
          "rules": [
            {
              "id": "[CRITICAL] CVE-1234-5678 foopackage",
              "name": "dockerfile_scan",
              "shortDescription": {
                "text": "CVE-1234-5678 Package: foopackage"
              },
              "fullDescription": {
                "text": "foovuln."
              },
              "helpUri": "https://avd.aquasec.com/nvd/cve-1234-5678",
              "help": {
                "text": "Vulnerability CVE-1234-5678\nSeverity: CRITICAL\nPackage: foopackage\nInstalled Version: 1.2.3\nFixed Version: 4.5.6\nLink: [CVE-1234-5678](https://avd.aquasec.com/nvd/cve-1234-5678)",
                "markdown": "**Vulnerability CVE-1234-5678**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|CRITICAL|foopackage|1.2.3|4.5.6|[CVE-1234-5678](https://avd.aquasec.com/nvd/cve-1234-5678)|\n"
              },
              "properties": {
                "tags": [
                  "vulnerability",
                  "CRITICAL",
                  "foopackage"
                ],
                "precision": "very-high"
              }
            }]
        }
      },
      "results": [
        {
          "ruleId": "[CRITICAL] CVE-1234-5678 foopackage",
          "ruleIndex": 0,
          "level": "error",
          "message": {
            "text": "foodesc."
          },
          "locations": [{
            "physicalLocation": {
              "artifactLocation": {
                "uri": "Dockerfile"
              },
              "region": {
                "startLine": 1,
                "startColumn": 1,
                "endColumn": 1
              }
            }
          }]
        }],
      "columnKind": "utf16CodeUnits"
    }
  ]
}`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			templateFile := "../../contrib/sarif.tpl"
			got := bytes.Buffer{}

			template, err := ioutil.ReadFile(templateFile)
			require.NoError(t, err, tc.name)

			inputResults := report.Results{
				report.Result{
					Target:          "footarget",
					Type:            "footype",
					Vulnerabilities: tc.detectedVulns,
				},
			}
			assert.NoError(t, report.WriteResults("template", &got, nil, inputResults, string(template), false), tc.name)
			assert.JSONEq(t, tc.want, got.String(), tc.name)
		})
	}
}

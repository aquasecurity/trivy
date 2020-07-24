package report_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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
			expectedOutput: `+---------+------------------+----------+-------------------+---------------+--------+
| LIBRARY | VULNERABILITY ID | SEVERITY | INSTALLED VERSION | FIXED VERSION | TITLE  |
+---------+------------------+----------+-------------------+---------------+--------+
| foo     |              123 | HIGH     | 1.2.3             | 3.4.5         | foobar |
+---------+------------------+----------+-------------------+---------------+--------+
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
			name: "no title for vuln",
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
					VulnerabilityID:  "123",
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:    "a b c d e f g h i j k l m n o p q r s t u v",
						Severity: "HIGH",
					},
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
			assert.NoError(t, report.WriteResults("table", &tableWritten, inputResults, "", tc.light), tc.name)
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
			expectedJSON: report.Results{
				report.Result{
					Target: "foojson",
					Vulnerabilities: []types.DetectedVulnerability{
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
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			jw := report.JsonWriter{}
			jsonWritten := bytes.Buffer{}
			jw.Output = &jsonWritten

			inputResults := report.Results{
				{
					Target:          "foojson",
					Vulnerabilities: tc.detectedVulns,
				},
			}

			assert.NoError(t, report.WriteResults("json", &jsonWritten, inputResults, "", false), tc.name)

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
					PkgName:          "foo",
					InstalledVersion: "1.2.3",
					FixedVersion:     "3.4.5",
					Vulnerability: dbTypes.Vulnerability{
						Title:       `gcc: POWER9 "DARN" RNG intrinsic produces repeated output`,
						Description: `curl version curl 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl < 7.20.0 and curl >= 7.60.0.`,
						Severity:    "HIGH",
					},
				},
			},

			template: `<testsuites>
{{- range . -}}
{{- $failures := len .Vulnerabilities }}
    <testsuite tests="1" failures="{{ $failures }}" time="" name="{{  .Target }}">
	{{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
        <testcase classname="{{ .PkgName }}-{{ .InstalledVersion }}" name="[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}" time="">
            <failure message={{escapeXML .Title | printf "%q" }} type="description">{{escapeXML .Description | printf "%q" }}</failure>
        </testcase>
    {{- end }}
	</testsuite>
{{- end }}
</testsuites>`,

			expected: `<testsuites>
    <testsuite tests="1" failures="1" time="" name="foojunit">
        <properties>
            <property name="type" value="test"></property>
        </properties>
        <testcase classname="foo-1.2.3" name="[HIGH] 123" time="">
            <failure message="gcc: POWER9 &#34;DARN&#34; RNG intrinsic produces repeated output" type="description">"curl version curl 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl &lt; 7.20.0 and curl &gt;= 7.60.0."</failure>
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
			},
			template: `{{ range . }}{{ range .Vulnerabilities}}{{.VulnerabilityID}} {{ endWithPeriod .Description | printf "%q" }}{{ end }}{{ end }}`,
			expected: `CVE-2019-0000 "without period."CVE-2019-0000 "with period."`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			tmplWritten := bytes.Buffer{}
			inputResults := report.Results{
				{
					Target:          "foojunit",
					Type:            "test",
					Vulnerabilities: tc.detectedVulns,
				},
			}

			assert.NoError(t, report.WriteResults("template", &tmplWritten, inputResults, tc.template, false))
			assert.Equal(t, tc.expected, tmplWritten.String())
		})
	}
}

func TestReportWriter_Sarif(t *testing.T) {
	testCases := []struct {
		name           string
		url            string
		expectedOutput string
		expectedError  string
	}{
		{
			name: "happy path",
			expectedOutput: `{
	"$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
	"version": "2.1.0",
	"runs": [{
		"tool": {
			"driver": {
				"name": "Trivy",
				"fullName": "Trivy Vulnerability Scanner",
				"rules": [{
						"id": "[MEDIUM] CVE-2019-0000",
						"name": "dockerfile_scan",
						"shortDescription": {
							"text": "CVE-2019-0000 Package: foo"
						},
						"fullDescription": {
							"text": "."
						},
						"help": {
							"text": "Vulnerability CVE-2019-0000\nSeverity: MEDIUM\nPackage: foo\nInstalled Version: 1.2.3\nFixed Version: 1.2.4\nLink: [CVE-2019-0000](https://aquasecurity.github.io/avd/nvd/cve-2019-0000)",
							"markdown": "**Vulnerability CVE-2019-0000**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|MEDIUM|foo|1.2.3|1.2.4|[CVE-2019-0000](https://aquasecurity.github.io/avd/nvd/cve-2019-0000)|\n"
						},
						"properties": {
							"tags": [
								"vulnerability",
								"MEDIUM",
								"foo"
							],
							"precision": "very-high"
						}
					},
					{
						"id": "[HIGH] CVE-2019-0001",
						"name": "dockerfile_scan",
						"shortDescription": {
							"text": "CVE-2019-0001 Package: bar"
						},
						"fullDescription": {
							"text": "."
						},
						"help": {
							"text": "Vulnerability CVE-2019-0001\nSeverity: HIGH\nPackage: bar\nInstalled Version: 2.3.4\nFixed Version: 2.3.5\nLink: [CVE-2019-0001](https://aquasecurity.github.io/avd/nvd/cve-2019-0001)",
							"markdown": "**Vulnerability CVE-2019-0001**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|HIGH|bar|2.3.4|2.3.5|[CVE-2019-0001](https://aquasecurity.github.io/avd/nvd/cve-2019-0001)|\n"
						},
						"properties": {
							"tags": [
								"vulnerability",
								"HIGH",
								"bar"
							],
							"precision": "very-high"
						}
					}
				]
			}
		},
		"results": [{
				"ruleId": "[MEDIUM] CVE-2019-0000",
				"ruleIndex": 0,
				"level": "error",
				"message": {
					"text": "without period."
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
			},
			{
				"ruleId": "[HIGH] CVE-2019-0001",
				"ruleIndex": 1,
				"level": "error",
				"message": {
					"text": "with period."
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
			}
		],
		"columnKind": "utf16CodeUnits"
	}]
}`,
		},
		{
			name:          "sad path, bad url",
			url:           "http://foo/bar/baz",
			expectedError: "no such host",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			oldDefaultSarifTemplateURL := report.DefaultSarifTemplateURL

			if tc.url == "" {
				ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					io.WriteString(w, `{
  "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0-rtm.4.json",
  "version": "2.1.0",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "Trivy",
          "fullName": "Trivy Vulnerability Scanner",
          "rules": [
        {{- $t_first := true }}
        {{- range . }}
            {{- range .Vulnerabilities -}}
              {{- if $t_first -}}
                {{- $t_first = false -}}
              {{ else -}}
                ,
              {{- end }}
            {
              "id": "[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}",
              "name": "dockerfile_scan",
              "shortDescription": {
                "text": "{{ .VulnerabilityID }} Package: {{ .PkgName }}"
              },
              "fullDescription": {
                "text": "{{ endWithPeriod .Title }}"
              },
              "help": {
                "text": "Vulnerability {{ .VulnerabilityID }}\nSeverity: {{ .Vulnerability.Severity }}\nPackage: {{ .PkgName }}\nInstalled Version: {{ .InstalledVersion }}\nFixed Version: {{ .FixedVersion }}\nLink: [{{ .VulnerabilityID }}](https://aquasecurity.github.io/avd/nvd/{{ .VulnerabilityID | toLower}})",
                "markdown": "**Vulnerability {{ .VulnerabilityID }}**\n| Severity | Package | Installed Version | Fixed Version | Link |\n| --- | --- | --- | --- | --- |\n|{{ .Vulnerability.Severity }}|{{ .PkgName }}|{{ .InstalledVersion }}|{{ .FixedVersion }}|[{{ .VulnerabilityID }}](https://aquasecurity.github.io/avd/nvd/{{ .VulnerabilityID | toLower }})|\n"
              },
              "properties": {
                "tags": [
                  "vulnerability",
                  "{{ .Vulnerability.Severity }}",
                  "{{ .PkgName }}"
                ],
                "precision": "very-high"
              }
            }
            {{- end -}}
         {{- end -}}
          ]
        }
      },
      "results": [
    {{- $t_first := true }}
    {{- range . }}
        {{- range $index, $vulnerability := .Vulnerabilities -}}
          {{- if $t_first -}}
            {{- $t_first = false -}}
          {{ else -}}
            ,
          {{- end }}
        {
          "ruleId": "[{{ $vulnerability.Vulnerability.Severity }}] {{ $vulnerability.VulnerabilityID }}",
          "ruleIndex": {{ $index }},
          "level": "error",
          "message": {
            "text": {{ endWithPeriod $vulnerability.Description | printf "%q" }}
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
        }
        {{- end -}}
      {{- end -}}
      ],
      "columnKind": "utf16CodeUnits"
    }
  ]
}`)
				}))
				report.DefaultSarifTemplateURL = ts.URL
				defer func() {
					ts.Close()
					report.DefaultSarifTemplateURL = oldDefaultSarifTemplateURL
				}()
			} else {
				oldDefaultSarifTemplateURL := report.DefaultSarifTemplateURL
				report.DefaultSarifTemplateURL = tc.url
				defer func() {
					report.DefaultSarifTemplateURL = oldDefaultSarifTemplateURL
				}()
			}

			tmplWritten := bytes.Buffer{}
			inputResults := report.Results{
				{
					Target: "sariftesttarget",
					Type:   "test",
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID: "CVE-2019-0000",
							PkgName:         "foo",
							Vulnerability: dbTypes.Vulnerability{
								Severity:    "MEDIUM",
								Description: "without period",
							},
							InstalledVersion: "1.2.3",
							FixedVersion:     "1.2.4",
						},
						{
							VulnerabilityID: "CVE-2019-0001",
							PkgName:         "bar",
							Vulnerability: dbTypes.Vulnerability{
								Severity:    "HIGH",
								Description: "with period.",
							},
							InstalledVersion: "2.3.4",
							FixedVersion:     "2.3.5",
						},
					},
				},
			}

			err := report.WriteResults("sarif", &tmplWritten, inputResults, "", false)
			switch {
			case tc.expectedError != "":
				assert.Contains(t, err.Error(), tc.expectedError, tc.name)
				assert.Empty(t, tmplWritten.String(), tc.name)
			default:
				assert.NoError(t, err, tc.name)
				assert.JSONEq(t, tc.expectedOutput, tmplWritten.String(), tc.name)
			}
		})
	}
}

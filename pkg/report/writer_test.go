package report_test

import (
	"bytes"
	"io/ioutil"
	"os"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
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
			input := report.Report{
				ImageID: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				Results: report.Results{
					{
						Target:          "foo",
						Vulnerabilities: tc.detectedVulns,
					},
				},
			}
			tableWritten := bytes.Buffer{}
			assert.NoError(t, report.Write("table", &tableWritten, nil, input, "", tc.light), tc.name)
			assert.Equal(t, tc.expectedOutput, tableWritten.String(), tc.name)
		})
	}
}

func TestReportWriter_JSON(t *testing.T) {
	testCases := []struct {
		name             string
		input            report.Report
		newSchema        bool
		expectedJSONFile string
	}{
		{
			name: "happy path",
			input: report.Report{
				ImageID:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				RepoTags:    []string{"test:latest"},
				RepoDigests: []string{"test@sha256:0bd0e9e03a022c3b0226667621da84fc9bf562a9056130424b5bfbd8bcb0397f"},
				Results: report.Results{
					{
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
			expectedJSONFile: "testdata/old.json.golden",
		},
		{
			name:      "new schema",
			newSchema: true,
			input: report.Report{
				ImageID:     "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				RepoTags:    []string{"test:latest"},
				RepoDigests: []string{"test@sha256:0bd0e9e03a022c3b0226667621da84fc9bf562a9056130424b5bfbd8bcb0397f"},
				Results: report.Results{
					{
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
			expectedJSONFile: "testdata/new.json.golden",
		},
	}

	log.InitLogger(false, false)
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.newSchema {
				os.Setenv("TRIVY_NEW_JSON_SCHEMA", "true")
			}
			output := &bytes.Buffer{}

			err := report.Write("json", output, nil, tc.input, "", false)
			require.NoError(t, err, tc.name)

			b, err := ioutil.ReadFile(tc.expectedJSONFile)
			require.NoError(t, err, tc.name)

			assert.JSONEq(t, string(b), output.String())
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
    <testsuite tests="1" failures="{{ $failures }}" time="" name="{{  .Target }}">
	{{- if not (eq .Type "") }}
        <properties>
            <property name="type" value="{{ .Type }}"></property>
        </properties>
        {{- end -}}
        {{ range .Vulnerabilities }}
        <testcase classname={{ printf "%v-%v" .PkgName .InstalledVersion | printf "%q" }} name="[{{ .Vulnerability.Severity }}] {{ .VulnerabilityID }}" time="">
            <failure message={{escapeXML .Title | printf "%q" }} type="description">{{ endWithPeriod (escapeString .Description) | printf "%q" }}</failure>
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
        <testcase classname="foo \\ test-1.2.3" name="[HIGH] 123" time="">
            <failure message="gcc: POWER9 &#34;DARN&#34; RNG intrinsic produces repeated output" type="description">"curl version curl \\X 7.20.0 to and including curl 7.59.0 contains a CWE-126: Buffer Over-read vulnerability in denial of service that can result in curl can be tricked into reading data beyond the end of a heap based buffer used to store downloaded RTSP content.. This vulnerability appears to have been fixed in curl &lt; 7.20.0 and curl &gt;= 7.60.0."</failure>
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
			input := report.Report{
				ImageID: "sha256:5c534be56eca62e756ef2ef51523feda0f19cd7c15bb0c015e3d6e3ae090bf6e",
				Results: report.Results{
					{
						Target:          "foojunit",
						Type:            "test",
						Vulnerabilities: tc.detectedVulns,
					},
				},
			}

			assert.NoError(t, report.Write("template", &tmplWritten, nil, input, tc.template, false))
			assert.Equal(t, tc.expected, tmplWritten.String())
		})
	}
}

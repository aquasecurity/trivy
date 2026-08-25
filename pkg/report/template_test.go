package report_test

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"

	"github.com/package-url/packageurl-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/clock"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

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
						VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
							"nvd": 1,
						},
					},
				},
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "bar",
					Vulnerability: dbTypes.Vulnerability{
						Severity: dbTypes.SeverityHigh.String(),
					},
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
			name: "custom JSON marshaler",
			detectedVulns: []types.DetectedVulnerability{
				{
					VulnerabilityID: "CVE-2019-0000",
					PkgName:         "foo",
					Status:          dbTypes.StatusAffected,
					PkgIdentifier: ftypes.PkgIdentifier{
						PURL: &packageurl.PackageURL{
							Type:    packageurl.TypeNPM,
							Name:    "foobar",
							Version: "1.2.3",
						},
					},
				},
			},
			template: `{{ range . }}{{ range .Vulnerabilities}}{{ toPrettyJson . }}{{ end }}{{ end }}`,
			expected: `{
  "VulnerabilityID": "CVE-2019-0000",
  "PkgName": "foo",
  "PkgIdentifier": {
    "PURL": "pkg:npm/foobar@1.2.3"
  },
  "Status": "affected"
}`,
		},
		{
			name:          "happy path: env var parsing",
			detectedVulns: []types.DetectedVulnerability{},
			template:      `{{ lower (env "AWS_ACCOUNT_ID") }}`,
			expected:      `123456789012`,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC))

			t.Setenv("AWS_ACCOUNT_ID", "123456789012")
			got := bytes.Buffer{}
			inputReport := types.Report{
				Results: types.Results{
					{
						Target:          "foojunit",
						Type:            "test",
						Vulnerabilities: tc.detectedVulns,
					},
				},
			}

			w, err := report.NewTemplateWriter(&got, tc.template, "dev")
			require.NoError(t, err)
			err = w.Write(ctx, inputReport)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, got.String())
		})
	}
}

// TestReportWriter_ASFFTemplate renders the ASFF template shipped in contrib/
// and checks that the package fields arrive intact. Package names and versions
// are taken from scanned manifests, so they may contain characters that are
// significant inside a JSON string.
func TestReportWriter_ASFFTemplate(t *testing.T) {
	testCases := []struct {
		name             string
		pkgName          string
		installedVersion string
		fixedVersion     string
	}{
		{
			name:             "plain package name and versions",
			pkgName:          "libcrypto1.1",
			installedVersion: "1.1.1c-r0",
			fixedVersion:     "1.1.1d-r0",
		},
		{
			name:             "double quote in the installed version",
			pkgName:          "openssl",
			installedVersion: `1.0", "Injected": "value`,
			fixedVersion:     "1.1.0",
		},
		{
			name:             "package name ending with a backslash",
			pkgName:          `openssl\`,
			installedVersion: "1.0.0",
			fixedVersion:     "1.1.0",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx := clock.With(t.Context(), time.Date(2020, 8, 10, 7, 28, 17, 958601, time.UTC))

			t.Setenv("AWS_ACCOUNT_ID", "123456789012")
			t.Setenv("AWS_REGION", "test-region")

			inputReport := types.Report{
				Results: types.Results{
					{
						Target: "alpine:3.10 (alpine 3.10.2)",
						Type:   "alpine",
						Vulnerabilities: []types.DetectedVulnerability{
							{
								VulnerabilityID:  "CVE-2019-1549",
								PkgName:          tc.pkgName,
								InstalledVersion: tc.installedVersion,
								FixedVersion:     tc.fixedVersion,
								Vulnerability: dbTypes.Vulnerability{
									Title:       "openssl: information disclosure",
									Description: "A description.",
									Severity:    dbTypes.SeverityMedium.String(),
								},
							},
						},
					},
				},
			}

			got := bytes.Buffer{}
			w, err := report.NewTemplateWriter(&got, "@../../contrib/asff.tpl", "dev")
			require.NoError(t, err)
			require.NoError(t, w.Write(ctx, inputReport))

			var asff struct {
				Findings []struct {
					Title     string `json:"Title"`
					Resources []struct {
						Details struct {
							Other map[string]string `json:"Other"`
						} `json:"Details"`
					} `json:"Resources"`
				} `json:"Findings"`
			}
			require.NoError(t, json.Unmarshal(got.Bytes(), &asff), "ASFF output must be valid JSON")

			require.Len(t, asff.Findings, 1)
			other := asff.Findings[0].Resources[0].Details.Other

			assert.Equal(t, tc.pkgName, other["PkgName"])
			assert.Equal(t, tc.installedVersion, other["Installed Package"])
			assert.Equal(t, tc.fixedVersion, other["Patched Package"])
			assert.Contains(t, asff.Findings[0].Title, tc.pkgName)

			// A field that escapes its string would show up as an extra key.
			assert.NotContains(t, other, "Injected")
		})
	}
}

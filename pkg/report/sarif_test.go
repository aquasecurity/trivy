package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func toPtr[T any](v T) *T {
	return &v
}

func TestReportWriter_Sarif(t *testing.T) {
	tests := []struct {
		name        string
		input       types.Results
		wantRules   []*sarif.ReportingDescriptor
		wantResults []*sarif.Result
	}{
		{
			name: "report with vulnerabilities",
			input: types.Results{
				{
					Target: "library/test",
					Class:  types.ClassOSPkg,
					Packages: []ftypes.Package{
						{
							Name:    "foo",
							Version: "1.2.3",
							Locations: []ftypes.Location{
								{
									StartLine: 5,
									EndLine:   10,
								},
								{
									StartLine: 15,
									EndLine:   20,
								},
							},
						},
					},
					Vulnerabilities: []types.DetectedVulnerability{
						{
							VulnerabilityID:  "CVE-2020-0001",
							PkgName:          "foo",
							InstalledVersion: "1.2.3",
							FixedVersion:     "3.4.5",
							PrimaryURL:       "https://avd.aquasec.com/nvd/cve-2020-0001",
							SeveritySource:   "redhat",
							Vulnerability: dbTypes.Vulnerability{
								Title:       "foobar",
								Description: "baz",
								Severity:    "HIGH",
								VendorSeverity: map[dbTypes.SourceID]dbTypes.Severity{
									vulnerability.NVD:    dbTypes.SeverityCritical,
									vulnerability.RedHat: dbTypes.SeverityHigh,
								},
								CVSS: map[dbTypes.SourceID]dbTypes.CVSS{
									vulnerability.NVD: {
										V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										V3Score:  9.8,
									},
									vulnerability.RedHat: {
										V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
										V3Score:  7.5,
									},
								},
							},
						},
					},
				},
			},
			wantRules: []*sarif.ReportingDescriptor{
				{
					ID:               "CVE-2020-0001",
					Name:             toPtr("OsPackageVulnerability"),
					ShortDescription: &sarif.MultiformatMessageString{Text: toPtr("foobar")},
					FullDescription:  &sarif.MultiformatMessageString{Text: toPtr("baz")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: toPtr("https://avd.aquasec.com/nvd/cve-2020-0001"),
					Properties: map[string]interface{}{
						"tags": []interface{}{
							"vulnerability",
							"security",
							"HIGH",
						},
						"precision":         "very-high",
						"security-severity": "7.5",
					},
					Help: &sarif.MultiformatMessageString{
						Text:     toPtr("Vulnerability CVE-2020-0001\nSeverity: HIGH\nPackage: foo\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)\nbaz"),
						Markdown: toPtr("**Vulnerability CVE-2020-0001**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|foo|3.4.5|[CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)|\n\nbaz"),
					},
				},
			},
			wantResults: []*sarif.Result{
				{
					RuleID:    toPtr("CVE-2020-0001"),
					RuleIndex: toPtr[uint](0),
					Level:     toPtr("error"),
					Message:   sarif.Message{Text: toPtr("Package: foo\nInstalled Version: 1.2.3\nVulnerability CVE-2020-0001\nSeverity: HIGH\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)")},
					Locations: []*sarif.Location{
						{
							Message: &sarif.Message{Text: toPtr("library/test: foo@1.2.3")},
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       toPtr("library/test"),
									URIBaseId: toPtr("ROOTPATH"),
								},
								Region: &sarif.Region{
									StartLine:   toPtr(5),
									EndLine:     toPtr(10),
									StartColumn: toPtr(1),
									EndColumn:   toPtr(1),
								},
							},
						},
						{
							Message: &sarif.Message{Text: toPtr("library/test: foo@1.2.3")},
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       toPtr("library/test"),
									URIBaseId: toPtr("ROOTPATH"),
								},
								Region: &sarif.Region{
									StartLine:   toPtr(15),
									EndLine:     toPtr(20),
									StartColumn: toPtr(1),
									EndColumn:   toPtr(1),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "report with misconfigurations",
			input: types.Results{
				{
					Target: "library/test",
					Class:  types.ClassConfig,
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
			wantResults: []*sarif.Result{
				{
					RuleID:    toPtr("KSV001"),
					RuleIndex: toPtr[uint](0),
					Level:     toPtr("error"),
					Message:   sarif.Message{Text: toPtr("Artifact: library/test\nType: \nVulnerability KSV001\nSeverity: HIGH\nMessage: Message\nLink: [KSV001](https://avd.aquasec.com/appshield/ksv001)")},
					Locations: []*sarif.Location{
						{
							Message: &sarif.Message{Text: toPtr("library/test")},
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       toPtr("library/test"),
									URIBaseId: toPtr("ROOTPATH"),
								},
								Region: &sarif.Region{
									StartLine:   toPtr(1),
									EndLine:     toPtr(1),
									StartColumn: toPtr(1),
									EndColumn:   toPtr(1),
								},
							},
						},
					},
				},
				{
					RuleID:    toPtr("KSV002"),
					RuleIndex: toPtr[uint](1),
					Level:     toPtr("error"),
					Message:   sarif.Message{Text: toPtr("Artifact: library/test\nType: \nVulnerability KSV002\nSeverity: CRITICAL\nMessage: Message\nLink: [KSV002](https://avd.aquasec.com/appshield/ksv002)")},
					Locations: []*sarif.Location{
						{
							Message: &sarif.Message{Text: toPtr("library/test")},
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       toPtr("library/test"),
									URIBaseId: toPtr("ROOTPATH"),
								},
								Region: &sarif.Region{
									StartLine:   toPtr(1),
									EndLine:     toPtr(1),
									StartColumn: toPtr(1),
									EndColumn:   toPtr(1),
								},
							},
						},
					},
				},
			},
			wantRules: []*sarif.ReportingDescriptor{
				{
					ID:               "KSV001",
					Name:             toPtr("Misconfiguration"),
					ShortDescription: &sarif.MultiformatMessageString{Text: toPtr("Image tag &#39;:latest&#39; used")},
					FullDescription:  &sarif.MultiformatMessageString{Text: toPtr("")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: toPtr("https://avd.aquasec.com/appshield/ksv001"),
					Properties: map[string]interface{}{
						"tags": []interface{}{
							"misconfiguration",
							"security",
							"HIGH",
						},
						"precision":         "very-high",
						"security-severity": "8.0",
					},
					Help: &sarif.MultiformatMessageString{
						Text:     toPtr("Misconfiguration KSV001\nType: Kubernetes Security Check\nSeverity: HIGH\nCheck: Image tag ':latest' used\nMessage: Message\nLink: [KSV001](https://avd.aquasec.com/appshield/ksv001)\n"),
						Markdown: toPtr("**Misconfiguration KSV001**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Kubernetes Security Check|HIGH|Image tag ':latest' used|Message|[KSV001](https://avd.aquasec.com/appshield/ksv001)|\n\n"),
					},
				},
				{
					ID:               "KSV002",
					Name:             toPtr("Misconfiguration"),
					ShortDescription: &sarif.MultiformatMessageString{Text: toPtr("SYS_ADMIN capability added")},
					FullDescription:  &sarif.MultiformatMessageString{Text: toPtr("")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: toPtr("https://avd.aquasec.com/appshield/ksv002"),
					Properties: map[string]interface{}{
						"tags": []interface{}{
							"misconfiguration",
							"security",
							"CRITICAL",
						},
						"precision":         "very-high",
						"security-severity": "9.5",
					},
					Help: &sarif.MultiformatMessageString{
						Text:     toPtr("Misconfiguration KSV002\nType: Kubernetes Security Check\nSeverity: CRITICAL\nCheck: SYS_ADMIN capability added\nMessage: Message\nLink: [KSV002](https://avd.aquasec.com/appshield/ksv002)\n"),
						Markdown: toPtr("**Misconfiguration KSV002**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Kubernetes Security Check|CRITICAL|SYS_ADMIN capability added|Message|[KSV002](https://avd.aquasec.com/appshield/ksv002)|\n\n"),
					},
				},
			},
		},
		{
			name: "report with secrets",
			input: types.Results{
				{
					Target: "library/test",
					Class:  types.ClassSecret,
					Secrets: []ftypes.SecretFinding{
						{
							RuleID:    "aws-secret-access-key",
							Category:  "AWS",
							Severity:  "CRITICAL",
							Title:     "AWS Secret Access Key",
							StartLine: 1,
							EndLine:   1,
							Match:     "'AWS_secret_KEY'=\"****************************************\"",
						},
					},
				},
			},
			wantResults: []*sarif.Result{
				{
					RuleID:    toPtr("aws-secret-access-key"),
					RuleIndex: toPtr[uint](0),
					Level:     toPtr("error"),
					Message:   sarif.Message{Text: toPtr("Artifact: library/test\nType: \nSecret AWS Secret Access Key\nSeverity: CRITICAL\nMatch: 'AWS_secret_KEY'=\"****************************************\"")},
					Locations: []*sarif.Location{
						{
							Message: &sarif.Message{Text: toPtr("library/test")},
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       toPtr("library/test"),
									URIBaseId: toPtr("ROOTPATH"),
								},
								Region: &sarif.Region{
									StartLine:   toPtr(1),
									EndLine:     toPtr(1),
									StartColumn: toPtr(1),
									EndColumn:   toPtr(1),
								},
							},
						},
					},
				},
			},
			wantRules: []*sarif.ReportingDescriptor{
				{
					ID:               "aws-secret-access-key",
					Name:             toPtr("Secret"),
					ShortDescription: &sarif.MultiformatMessageString{Text: toPtr("AWS Secret Access Key")},
					FullDescription:  &sarif.MultiformatMessageString{Text: toPtr("\u0026#39;AWS_secret_KEY\u0026#39;=\u0026#34;****************************************\u0026#34;")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: toPtr("https://github.com/aquasecurity/trivy/blob/main/pkg/fanal/secret/builtin-rules.go"),
					Properties: map[string]interface{}{
						"tags": []interface{}{
							"secret",
							"security",
							"CRITICAL",
						},
						"precision":         "very-high",
						"security-severity": "9.5",
					},
					Help: &sarif.MultiformatMessageString{
						Text:     toPtr("Secret AWS Secret Access Key\nSeverity: CRITICAL\nMatch: 'AWS_secret_KEY'=\"****************************************\""),
						Markdown: toPtr("**Secret AWS Secret Access Key**\n| Severity | Match |\n| --- | --- |\n|CRITICAL|'AWS_secret_KEY'=\"****************************************\"|"),
					},
				},
			},
		},
		{
			name:        "no vulns",
			wantResults: []*sarif.Result{},
			wantRules:   []*sarif.ReportingDescriptor{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sarifWritten := bytes.Buffer{}
			err := report.Write(types.Report{Results: tt.input}, report.Option{
				Format: "sarif",
				Output: &sarifWritten,
			})
			assert.NoError(t, err)

			result := &sarif.Report{}
			err = json.Unmarshal(sarifWritten.Bytes(), result)
			assert.NoError(t, err)
			assert.Equal(t, tt.wantRules, result.Runs[0].Tool.Driver.Rules, tt.name)
			assert.Equal(t, tt.wantResults, result.Runs[0].Results, tt.name)
		})
	}
}

func TestToPathUri(t *testing.T) {
	tests := []struct {
		input  string
		output string
	}{
		{
			input:  "almalinux@sha256:08042694fffd61e6a0b3a22dadba207c8937977915ff6b1879ad744fd6638837",
			output: "library/almalinux",
		},
		{
			input:  "alpine:latest (alpine 3.13.4)",
			output: "library/alpine",
		},
		{
			input:  "docker.io/my-organization/my-app:2c6912aee7bde44b84d810aed106ca84f40e2e29",
			output: "my-organization/my-app",
		},
	}

	for _, test := range tests {
		got := report.ToPathUri(test.input)
		if got != test.output {
			t.Errorf("toPathUri(%q) got %q, wanted %q", test.input, got, test.output)
		}
	}
}

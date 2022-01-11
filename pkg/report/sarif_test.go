package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

func getStringPointer(s string) *string {
	return &s
}
func getUintPointer(i uint) *uint {
	return &i
}
func getIntPointer(i int) *int {
	return &i
}
func TestReportWriter_Sarif(t *testing.T) {
	tests := []struct {
		name        string
		input       report.Results
		wantRules   []*sarif.ReportingDescriptor
		wantResults []*sarif.Result
	}{
		{
			name: "report with vulnerabilities",
			input: report.Results{
				{
					Target: "test",
					Class:  report.ClassOSPkg,
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
								CVSS: map[string]dbTypes.CVSS{
									"nvd": {
										V3Vector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
										V3Score:  9.8,
									},
									"redhat": {
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
					Name:             getStringPointer("OsPackageVulnerability"),
					ShortDescription: &sarif.MultiformatMessageString{Text: getStringPointer("CVE-2020-0001")},
					FullDescription:  &sarif.MultiformatMessageString{Text: getStringPointer("baz")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: getStringPointer("https://avd.aquasec.com/nvd/cve-2020-0001"),
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
						Text:     getStringPointer("Vulnerability CVE-2020-0001\nSeverity: HIGH\nPackage: foo\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)\nbaz"),
						Markdown: getStringPointer("**Vulnerability CVE-2020-0001**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|foo|3.4.5|[CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)|\n\nbaz"),
					},
				},
			},
			wantResults: []*sarif.Result{
				{
					RuleID:    getStringPointer("CVE-2020-0001"),
					RuleIndex: getUintPointer(0),
					Level:     getStringPointer("error"),
					Message:   sarif.Message{Text: getStringPointer("Package: foo\nInstalled Version: 1.2.3\nVulnerability CVE-2020-0001\nSeverity: HIGH\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)")},
					Locations: []*sarif.Location{
						{
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       getStringPointer("test"),
									URIBaseId: getStringPointer("ROOTPATH"),
								},
								Region: &sarif.Region{StartLine: getIntPointer(1)},
							},
						},
					},
				},
			},
		},
		{
			name: "report with misconfigurations",
			input: report.Results{
				{
					Target: "test",
					Class:  report.ClassConfig,
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
					RuleID:    getStringPointer("KSV001"),
					RuleIndex: getUintPointer(0),
					Level:     getStringPointer("error"),
					Message:   sarif.Message{Text: getStringPointer("Artifact: test\nType: \nVulnerability KSV001\nSeverity: HIGH\nMessage: Message\nLink: [KSV001](https://avd.aquasec.com/appshield/ksv001)")},
					Locations: []*sarif.Location{
						{
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       getStringPointer("test"),
									URIBaseId: getStringPointer("ROOTPATH"),
								},
								Region: &sarif.Region{StartLine: getIntPointer(1)},
							},
						},
					},
				},
				{
					RuleID:    getStringPointer("KSV002"),
					RuleIndex: getUintPointer(1),
					Level:     getStringPointer("error"),
					Message:   sarif.Message{Text: getStringPointer("Artifact: test\nType: \nVulnerability KSV002\nSeverity: CRITICAL\nMessage: Message\nLink: [KSV002](https://avd.aquasec.com/appshield/ksv002)")},
					Locations: []*sarif.Location{
						{
							PhysicalLocation: &sarif.PhysicalLocation{
								ArtifactLocation: &sarif.ArtifactLocation{
									URI:       getStringPointer("test"),
									URIBaseId: getStringPointer("ROOTPATH"),
								},
								Region: &sarif.Region{StartLine: getIntPointer(1)},
							},
						},
					},
				},
			},
			wantRules: []*sarif.ReportingDescriptor{
				{
					ID:               "KSV001",
					Name:             getStringPointer("Misconfiguration"),
					ShortDescription: &sarif.MultiformatMessageString{Text: getStringPointer("KSV001")},
					FullDescription:  &sarif.MultiformatMessageString{Text: getStringPointer("")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: getStringPointer("https://avd.aquasec.com/appshield/ksv001"),
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
						Text:     getStringPointer("Misconfiguration KSV001\nType: Kubernetes Security Check\nSeverity: HIGH\nCheck: Image tag ':latest' used\nMessage: Message\nLink: [KSV001](https://avd.aquasec.com/appshield/ksv001)\n"),
						Markdown: getStringPointer("**Misconfiguration KSV001**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Kubernetes Security Check|HIGH|Image tag ':latest' used|Message|[KSV001](https://avd.aquasec.com/appshield/ksv001)|\n\n"),
					},
				},
				{
					ID:               "KSV002",
					Name:             getStringPointer("Misconfiguration"),
					ShortDescription: &sarif.MultiformatMessageString{Text: getStringPointer("KSV002")},
					FullDescription:  &sarif.MultiformatMessageString{Text: getStringPointer("")},
					DefaultConfiguration: &sarif.ReportingConfiguration{
						Level: "error",
					},
					HelpURI: getStringPointer("https://avd.aquasec.com/appshield/ksv002"),
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
						Text:     getStringPointer("Misconfiguration KSV002\nType: Kubernetes Security Check\nSeverity: CRITICAL\nCheck: SYS_ADMIN capability added\nMessage: Message\nLink: [KSV002](https://avd.aquasec.com/appshield/ksv002)\n"),
						Markdown: getStringPointer("**Misconfiguration KSV002**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|Kubernetes Security Check|CRITICAL|SYS_ADMIN capability added|Message|[KSV002](https://avd.aquasec.com/appshield/ksv002)|\n\n"),
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
			err := report.Write(report.Report{Results: tt.input}, report.Option{
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

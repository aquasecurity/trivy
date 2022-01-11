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
	testCases := []struct {
		name            string
		results         report.Results
		expectedRules   []*sarif.ReportingDescriptor
		expectedResults []*sarif.Result
	}{
		{
			name: "report with vulnerabilities",
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
			expectedRules: []*sarif.ReportingDescriptor{
				{
					ID:               "CVE-2020-0001",
					Name:             getStringPointer("UnknownIssue"),
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
							"8.0",
						},
						"precision":         "very-high",
						"security-severity": "8.0",
					},
					Help: &sarif.MultiformatMessageString{
						Text:     getStringPointer("Vulnerability CVE-2020-0001\nSeverity: HIGH\nPackage: foo\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)\nbaz"),
						Markdown: getStringPointer("**Vulnerability CVE-2020-0001**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|foo|3.4.5|[CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)|\n\nbaz"),
					},
				},
			},
			expectedResults: []*sarif.Result{
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
			expectedResults: []*sarif.Result{
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
			expectedRules: []*sarif.ReportingDescriptor{
				{
					ID:               "KSV001",
					Name:             getStringPointer("UnknownIssue"),
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
							"8.0",
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
					Name:             getStringPointer("UnknownIssue"),
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
							"9.5",
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
			name:            "no vulns",
			expectedResults: []*sarif.Result{},
			expectedRules:   []*sarif.ReportingDescriptor{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			sarifWritten := bytes.Buffer{}
			err := report.Write(report.Report{Results: tc.results}, report.Option{
				Format: "sarif",
				Output: &sarifWritten,
			})
			assert.NoError(t, err)

			result := &sarif.Report{}
			err = json.Unmarshal(sarifWritten.Bytes(), result)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRules, result.Runs[0].Tool.Driver.Rules, tc.name)
			assert.Equal(t, tc.expectedResults, result.Runs[0].Results, tc.name)
		})
	}
}

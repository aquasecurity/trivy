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
			name: "happy path vulnerabilities",
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
					Name:             getStringPointer("OtherVulnerability"),
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
						"security-severity": 8.0,
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
		/*
			{
				name: "happy path misconfigurations",
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
				expectedResults: []sarifResult{},
				expectedRules:   []sarifRule{},
			},

			{
				name:            "no vulns",
				expectedResults: []sarifResult{},
				expectedRules:   []sarifRule{},
			},
		*/
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

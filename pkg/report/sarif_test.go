package report_test

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

type sarifTemplate struct {
	Schema string      `json:"$schema"`
	Runs   []sarifRuns `json:"runs"`
}
type sarifRuns struct {
	Tool    sarifTool     `json:"tool"`
	Results []sarifResult `json:"results"`
}
type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}
type sarifDriver struct {
	Rules []sarifRule
}
type sarifRule struct {
	Id               string                `json:"id"`
	ShortDescription sarifShortDescription `json:"shortDescription"`
	FullDescription  sarifFullDescription  `json:"fullDescription"`
	Help             sarifHelp             `json:"help"`
}
type sarifShortDescription struct {
	Text string `json:"text"`
}
type sarifFullDescription struct {
	Text string `json:"text"`
}
type sarifHelp struct {
	Text     string `json:"text"`
	Markdown string `json:"markdown"`
}

type sarifResult struct {
	RuleId    string           `json:"ruleId"`
	RuleIndex int              `json:"ruleIndex"`
	Level     string           `json:"level"`
	Message   sarifMessage     `json:"message"`
	Locations []sarifLocations `json:"locations"`
}
type sarifLocations struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}
type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}
type sarifArtifactLocation struct {
	Uri string `json:"uri"`
}
type sarifRegion struct {
	StartLine int `json:"startLine"`
}
type sarifMessage struct {
	Text string `json:"text"`
}

func TestReportWriter_Sarif(t *testing.T) {
	testCases := []struct {
		name            string
		results         report.Results
		expectedRules   []sarifRule
		expectedResults []sarifResult
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
			expectedRules: []sarifRule{
				{
					Id:               "CVE-2020-0001",
					ShortDescription: sarifShortDescription{Text: "CVE-2020-0001"},
					FullDescription:  sarifFullDescription{Text: "baz"},
					Help: sarifHelp{
						Text:     "Vulnerability CVE-2020-0001\nSeverity: HIGH\nPackage: foo\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)\nbaz",
						Markdown: "**Vulnerability CVE-2020-0001**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|HIGH|foo|3.4.5|[CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)|\n\nbaz",
					},
				},
			},
			expectedResults: []sarifResult{
				{
					RuleId:    "CVE-2020-0001",
					RuleIndex: 0,
					Level:     "error",
					Message:   sarifMessage{Text: "Package: foo\nInstalled Version: 1.2.3\nVulnerability CVE-2020-0001\nSeverity: HIGH\nFixed Version: 3.4.5\nLink: [CVE-2020-0001](https://avd.aquasec.com/nvd/cve-2020-0001)"},
					Locations: []sarifLocations{{PhysicalLocation: sarifPhysicalLocation{
						ArtifactLocation: sarifArtifactLocation{Uri: "test"},
						Region:           sarifRegion{StartLine: 1},
					}}},
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

			result := &sarifTemplate{}
			err = json.Unmarshal(sarifWritten.Bytes(), result)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedRules, result.Runs[0].Tool.Driver.Rules, tc.name)
			assert.Equal(t, tc.expectedResults, result.Runs[0].Results, tc.name)
		})
	}
}

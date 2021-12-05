package report

import (
	"github.com/owenrumney/go-sarif/sarif"
	"io"
)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output io.Writer
}

func (sw SarifWriter) Write(report Report) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}
	run := sarif.NewRun("Trivy", "https://github.com/aquasecurity/trivy")
	run.Tool.Driver.WithVersion("0.15.0")

	sarifReport.AddRun(run)

	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			help := vuln.Description
			if help == "" {
				help = vuln.Title
			}
			rule := run.AddRule(vuln.VulnerabilityID).
				WithDescription(vuln.VulnerabilityID).
				WithName(toSarifRuleName(res.Type)).
				WithFullDescription(&sarif.MultiformatMessageString{
					Text: vuln.Title,
				}).
				WithProperties(sarif.Properties{
					"tags": []string{
						"vulnerability",
						vuln.Severity,
					},
					"precision": "very-high",
				}).
				WithHelp(help)

			message := sarif.NewTextMessage(vuln.Description)
			region := sarif.NewSimpleRegion(1, 1)

			level := toSarifErrorLevel(vuln.Severity)

			location := sarif.NewPhysicalLocation().
				WithArtifactLocation(sarif.NewSimpleArtifactLocation(res.Target).WithUriBaseId("ROOTPATH")).
				WithRegion(region)

			ruleResult := run.AddResult(rule.ID)

			ruleResult.WithMessage(message).
				WithLevel(level).
				WithLocation(sarif.NewLocation().WithPhysicalLocation(location))
		}
	}
	return sarifReport.PrettyWrite(sw.Output)
}

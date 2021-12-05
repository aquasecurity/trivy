package report

import (
	"github.com/aquasecurity/defsec/formatters"
	"github.com/aquasecurity/defsec/provider"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/types"
	"io"
	"strings"
)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output io.Writer
}

func buildRuleResult(filename, description, sev string) rules.Result {
	result := rules.Result{}
	rng := types.NewRange(filename, 1, 1)
	md := types.NewMetadata(&rng, &types.FakeReference{})
	result.OverrideIssueBlockMetadata(&md)
	result.OverrideSeverity(severity.StringToSeverity(sev))
	result.OverrideDescription(description)
	result.OverrideAnnotation("annotation")
	return result
}

func parseVulnerabilityId(avdId string) (prvdr provider.Provider, service, shortcode string) {
	avds := strings.Split(avdId, "-")
	for i := range avds {
		switch i {
		case 0:
			prvdr = provider.Provider(avds[i])
		case 1:
			service = avds[i]
		case 2:
			shortcode = avds[i]
		}
	}
	return
}

func (sw SarifWriter) Write(report Report) error {
	results := rules.Results{}
	for _, r := range report.Results {
		for _, vuln := range r.Vulnerabilities {
			prvd, srv, shortCode := parseVulnerabilityId(vuln.VulnerabilityID)
			res := buildRuleResult(r.Target, vuln.Description, vuln.Severity)
			results.SetRule(rules.Rule{
				AVDID:       vuln.VulnerabilityID,
				ShortCode:   shortCode,
				Summary:     vuln.Description,
				Explanation: "",
				Impact:      "",
				Resolution:  "",
				Provider:    prvd,
				Service:     srv,
				Links:       []string{vuln.PrimaryURL},
				Severity:    severity.StringToSeverity(vuln.Severity),
			})
			results = append(results, res)
		}

	}
	return formatters.FormatSarif(sw.Output, results, "")
}

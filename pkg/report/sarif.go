package report

import (
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"

	"github.com/owenrumney/go-sarif/v2/sarif"
)

// regex to extract file path in case string includes (distro:version)
var re = regexp.MustCompile(`(?P<path>.+?)(?:\s*\((?:.*?)\).*?)?$`)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output  io.Writer
	Version string
	run     *sarif.Run
}

type sarifData struct {
	vulnerabilityId  string
	fullDescription  string
	helpText         string
	helpMarkdown     string
	resourceType     string
	severity         string
	url              string
	resultIndex      int
	artifactLocation string
	message          string
}

func (sw *SarifWriter) addSarifRule(data *sarifData) {
	r := sw.run.AddRule(data.vulnerabilityId).
		WithName(toSarifRuleName(data.resourceType)).
		WithDescription(data.vulnerabilityId).
		WithFullDescription(&sarif.MultiformatMessageString{Text: &data.fullDescription}).
		WithHelp(&sarif.MultiformatMessageString{
			Text:     &data.helpText,
			Markdown: &data.helpMarkdown,
		}).
		WithDefaultConfiguration(&sarif.ReportingConfiguration{
			Level: toSarifErrorLevel(data.severity),
		}).
		WithProperties(sarif.Properties{
			"tags": []string{
				"vulnerability",
				data.severity,
			},
			"precision": "very-high",
		})
	if data.url != "" {
		r.WithHelpURI(data.url)
	}
}

func (sw *SarifWriter) addSarifResult(data *sarifData) {
	sw.addSarifRule(data)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(data.artifactLocation).WithUriBaseId("ROOTPATH")).
		WithRegion(sarif.NewRegion().WithStartLine(1))
	result := sarif.NewRuleResult(data.vulnerabilityId).
		WithRuleIndex(data.resultIndex).
		WithMessage(sarif.NewTextMessage(data.message)).
		WithLevel(toSarifErrorLevel(data.severity)).
		WithLocations([]*sarif.Location{sarif.NewLocation().WithPhysicalLocation(location)})
	sw.run.AddResult(result)
}

func getRuleIndex(id string, indexes map[string]int) int {
	if i, ok := indexes[id]; ok {
		return i
	} else {
		l := len(indexes)
		indexes[id] = l
		return l
	}
}

func (sw SarifWriter) Write(report Report) error {
	sarifReport, err := sarif.New(sarif.Version210)
	if err != nil {
		return err
	}
	sw.run = sarif.NewRunWithInformationURI("Trivy", "https://github.com/aquasecurity/trivy")
	sw.run.Tool.Driver.WithVersion(sw.Version)
	sw.run.Tool.Driver.WithFullName("Trivy Vulnerability Scanner")

	ruleIndexes := map[string]int{}
	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			fullDescription := vuln.Description
			if fullDescription == "" {
				fullDescription = vuln.Title
			}

			sw.addSarifResult(&sarifData{
				vulnerabilityId:  vuln.VulnerabilityID,
				severity:         vuln.Severity,
				url:              vuln.PrimaryURL,
				resourceType:     res.Type,
				artifactLocation: toPathUri(res.Target),
				resultIndex:      getRuleIndex(vuln.VulnerabilityID, ruleIndexes),
				fullDescription:  html.EscapeString(fullDescription),
				helpText: fmt.Sprintf("Vulnerability %v\nSeverity: %v\nPackage: %v\nFixed Version: %v\nLink: [%v](%v)\n%v",
					vuln.VulnerabilityID, vuln.Severity, vuln.PkgName, vuln.FixedVersion, vuln.VulnerabilityID, vuln.PrimaryURL, vuln.Description),
				helpMarkdown: fmt.Sprintf("**Vulnerability %v**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|%v|%v|%v|[%v](%v)|\n\n%v",
					vuln.VulnerabilityID, vuln.Severity, vuln.PkgName, vuln.FixedVersion, vuln.VulnerabilityID, vuln.PrimaryURL, vuln.Description),
				message: fmt.Sprintf("Package: %v\nInstalled Version: %v\nVulnerability %v\nSeverity: %v\nFixed Version: %v\nLink: [%v](%v)",
					vuln.PkgName, vuln.InstalledVersion, vuln.VulnerabilityID, vuln.Severity, vuln.FixedVersion, vuln.VulnerabilityID, vuln.PrimaryURL),
			})
		}
		for _, misconf := range res.Misconfigurations {
			sw.addSarifResult(&sarifData{
				vulnerabilityId:  misconf.ID,
				severity:         misconf.Severity,
				url:              misconf.PrimaryURL,
				resourceType:     res.Type,
				artifactLocation: toPathUri(res.Target),
				resultIndex:      getRuleIndex(misconf.ID, ruleIndexes),
				fullDescription:  html.EscapeString(misconf.Description),
				helpText: fmt.Sprintf("Misconfiguration %v\nType: %s\nSeverity: %v\nCheck: %v\nMessage: %v\nLink: [%v](%v)\n%s",
					misconf.ID, misconf.Type, misconf.Severity, misconf.Title, misconf.Message, misconf.ID, misconf.PrimaryURL, misconf.Description),
				helpMarkdown: fmt.Sprintf("**Misconfiguration %v**\n| Type | Severity | Check | Message | Link |\n| --- | --- | --- | --- | --- |\n|%v|%v|%v|%s|[%v](%v)|\n\n%v",
					misconf.ID, misconf.Type, misconf.Severity, misconf.Title, misconf.Message, misconf.ID, misconf.PrimaryURL, misconf.Description),
				message: fmt.Sprintf("Artifact: %v\nType: %v\nVulnerability %v\nSeverity: %v\nMessage: %v\nLink: [%v](%v)",
					res.Target, res.Type, misconf.ID, misconf.Severity, misconf.Message, misconf.ID, misconf.PrimaryURL),
			})
		}
	}
	sarifReport.AddRun(sw.run)
	return sarifReport.PrettyWrite(sw.Output)
}

func toSarifRuleName(vulnerabilityType string) string {
	switch vulnerabilityType {
	case vulnerability.Ubuntu, vulnerability.Alpine, vulnerability.RedHat, vulnerability.RedHatOVAL,
		vulnerability.Debian, vulnerability.DebianOVAL, vulnerability.Fedora, vulnerability.Amazon,
		vulnerability.OracleOVAL, vulnerability.SuseCVRF, vulnerability.OpenSuseCVRF, vulnerability.Photon,
		vulnerability.CentOS:
		return "OsPackageVulnerability"
	case "npm", "yarn", "nuget", "pipenv", "poetry", "bundler", "cargo", "composer":
		return "ProgrammingLanguageVulnerability"
	default:
		return "OtherVulnerability"
	}
}

func toSarifErrorLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return "error"
	case "MEDIUM":
		return "warning"
	case "LOW", "UNKNOWN":
		return "note"
	default:
		return "none"
	}
}

func toPathUri(input string) string {
	var matches = re.FindStringSubmatch(input)
	if matches != nil {
		input = matches[re.SubexpIndex("path")]
	}
	return strings.ReplaceAll(input, "\\", "/")
}

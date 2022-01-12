package report

import (
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	sarifOsPackageVulnerability        = "OsPackageVulnerability"
	sarifLanguageSpecificVulnerability = "LanguageSpecificPackageVulnerability"
	sarifConfigFiles                   = "Misconfiguration"
	sarifUnknownIssue                  = "UnknownIssue"

	sarifError   = "error"
	sarifWarning = "warning"
	sarifNote    = "note"
	sarifNone    = "none"

	columnKind = "utf16CodeUnits"
)

var (
	rootPath = "file:///"

	// pathRegex to extract file path in case string includes (distro:version)
	pathRegex = regexp.MustCompile(`(?P<path>.+?)(?:\s*\((?:.*?)\).*?)?$`)
)

// SarifWriter implements result Writer
type SarifWriter struct {
	Output  io.Writer
	Version string
	run     *sarif.Run
}

type sarifData struct {
	title            string
	vulnerabilityId  string
	fullDescription  string
	helpText         string
	helpMarkdown     string
	resourceClass    string
	severity         string
	url              string
	resultIndex      int
	artifactLocation string
	message          string
	cvssScore        string
}

func (sw *SarifWriter) addSarifRule(data *sarifData) {
	r := sw.run.AddRule(data.vulnerabilityId).
		WithName(toSarifRuleName(data.resourceClass)).
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
				data.title,
				"security",
				data.severity,
			},
			"precision":         "very-high",
			"security-severity": data.cvssScore,
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
		return xerrors.Errorf("error creating a new sarif template: %w", err)
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
			path := vuln.PkgPath
			if path == "" {
				path = res.Target
			}
			sw.addSarifResult(&sarifData{
				title:            "vulnerability",
				vulnerabilityId:  vuln.VulnerabilityID,
				severity:         vuln.Severity,
				cvssScore:        getCVSSScore(vuln),
				url:              vuln.PrimaryURL,
				resourceClass:    string(res.Class),
				artifactLocation: toPathUri(path),
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
				title:            "misconfiguration",
				vulnerabilityId:  misconf.ID,
				severity:         misconf.Severity,
				cvssScore:        severityToScore(misconf.Severity),
				url:              misconf.PrimaryURL,
				resourceClass:    string(res.Class),
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
	sw.run.ColumnKind = columnKind
	sw.run.OriginalUriBaseIDs = map[string]*sarif.ArtifactLocation{
		"ROOTPATH": {URI: &rootPath},
	}
	sarifReport.AddRun(sw.run)
	return sarifReport.PrettyWrite(sw.Output)
}

func toSarifRuleName(class string) string {
	switch class {
	case ClassOSPkg:
		return sarifOsPackageVulnerability
	case ClassLangPkg:
		return sarifLanguageSpecificVulnerability
	case ClassConfig:
		return sarifConfigFiles
	default:
		return sarifUnknownIssue
	}
}

func toSarifErrorLevel(severity string) string {
	switch severity {
	case "CRITICAL", "HIGH":
		return sarifError
	case "MEDIUM":
		return sarifWarning
	case "LOW", "UNKNOWN":
		return sarifNote
	default:
		return sarifNone
	}
}

func toPathUri(input string) string {
	var matches = pathRegex.FindStringSubmatch(input)
	if matches != nil {
		input = matches[pathRegex.SubexpIndex("path")]
	}
	return strings.ReplaceAll(input, "\\", "/")
}

func getCVSSScore(vuln types.DetectedVulnerability) string {
	// Take the vendor score
	if cvss, ok := vuln.CVSS[vuln.SeveritySource]; ok {
		return fmt.Sprintf("%.1f", cvss.V3Score)
	}

	// Converts severity to score
	return severityToScore(vuln.Severity)
}

func severityToScore(severity string) string {
	switch severity {
	case "CRITICAL":
		return "9.5"
	case "HIGH":
		return "8.0"
	case "MEDIUM":
		return "5.5"
	case "LOW":
		return "2.0"
	default:
		return "0.0"
	}
}

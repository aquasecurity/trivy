package report

import (
	"fmt"
	"html"
	"io"
	"regexp"
	"strings"

	"github.com/owenrumney/go-sarif/v2/sarif"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
)

const (
	sarifOsPackageVulnerability        = "OsPackageVulnerability"
	sarifLanguageSpecificVulnerability = "LanguageSpecificPackageVulnerability"
	sarifConfigFiles                   = "ConfigFileMisconfiguration"
	sarifOtherVulnerability            = "OtherVulnerability"
	sarifError                         = "error"
	sarifWarning                       = "warning"
	sarifNote                          = "note"
	sarifNone                          = "none"
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
				"security",
				data.severity,
			},
			"precision":         "very-high",
			"security-severity": sarifSeverityLevel(data.severity),
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
				vulnerabilityId:  vuln.VulnerabilityID,
				severity:         vuln.Severity,
				url:              vuln.PrimaryURL,
				resourceType:     res.Type,
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
	case os.RedHat, os.Debian, os.Ubuntu, os.CentOS, os.Rocky, os.Alma, os.Fedora,
		os.Amazon, os.Oracle, os.OpenSUSE, os.OpenSUSELeap, os.OpenSUSETumbleweed, os.SLES,
		os.Photon, os.Alpine, os.Windows:
		return sarifOsPackageVulnerability

	case types.Bundler, types.GemSpec, types.Cargo, types.Composer, types.Npm, types.NuGet, types.Pip,
		types.Pipenv, types.Poetry, types.PythonPkg, types.NodePkg, types.Yarn, types.Jar, types.Pom,
		types.GoBinary, types.GoMod, types.JavaScript:
		return sarifLanguageSpecificVulnerability

	case types.YAML, types.JSON, types.TOML, types.Dockerfile, types.HCL, types.Terraform,
		types.Kubernetes, types.CloudFormation, types.Ansible:
		return sarifConfigFiles

	default:
		return sarifOtherVulnerability
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
	var matches = re.FindStringSubmatch(input)
	if matches != nil {
		input = matches[re.SubexpIndex("path")]
	}
	return strings.ReplaceAll(input, "\\", "/")
}

func sarifSeverityLevel(severity string) float32 {
	switch severity {
	case "CRITICAL":
		return 9.0
	case "HIGH":
		return 8.0
	case "MEDIUM":
		return 5.0
	case "LOW":
		return 3.5
	default:
		return 0.0
	}
}

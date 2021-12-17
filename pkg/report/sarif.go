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
	caption          string
	vulnerabilityId  string
	title            string
	description      string
	severity         string
	pkgName          string
	installedVersion string
	fixedVersion     string
	url              string
	resourceType     string
	filePath         string
	resultIndex      int
}

func (sw *SarifWriter) addSarifRule(data *sarifData) {
	description := data.description
	if description == "" {
		description = data.title
	}

	helpText := fmt.Sprintf("%s %v\n%v\nSeverity: %v\nPackage: %v\nFixed Version: %v\nLink: [%v](%v)",
		data.caption, data.vulnerabilityId, description, data.severity, data.pkgName, data.fixedVersion, data.vulnerabilityId, data.url)
	helpMarkdown := fmt.Sprintf("**%s %v**\n| Severity | Package | Fixed Version | Link |\n| --- | --- | --- | --- |\n|%v|%v|%v|[%v](%v)|\n%v\n",
		data.caption, data.vulnerabilityId, data.severity, data.pkgName, data.fixedVersion, data.vulnerabilityId, data.url, description)
	help := &sarif.MultiformatMessageString{
		Text:     &helpText,
		Markdown: &helpMarkdown,
	}

	fullDescription := data.title
	if fullDescription == "" {
		fullDescription = data.description
	}
	fullDescription = html.EscapeString(fullDescription)

	r := sw.run.AddRule(data.vulnerabilityId).
		WithName(toSarifRuleName(data.resourceType)).
		WithDescription(data.vulnerabilityId).
		WithFullDescription(&sarif.MultiformatMessageString{Text: &fullDescription}).
		WithHelp(help).
		WithMarkdownHelp(helpMarkdown).
		WithProperties(sarif.Properties{
			"tags": []string{
				"vulnerability",
				data.severity,
			},
			"precision": "very-high",
		})

	r.DefaultConfiguration = &sarif.ReportingConfiguration{
		Level: toSarifErrorLevel(data.severity),
	}

	if data.url != "" {
		r.WithHelpURI(data.url)
	}
}

func (sw *SarifWriter) addSarifResult(data *sarifData) {
	sw.addSarifRule(data)

	message := sarif.NewTextMessage(fmt.Sprintf("Package: %v\nInstalled Version: %v\nVulnerability %v\nSeverity: %v\nFixed Version: %v\nLink: [%v](%v)",
		data.pkgName, data.installedVersion, data.vulnerabilityId, data.severity, data.fixedVersion, data.vulnerabilityId, data.url))
	region := sarif.NewRegion().WithStartLine(1)

	location := sarif.NewPhysicalLocation().
		WithArtifactLocation(sarif.NewSimpleArtifactLocation(data.filePath).WithUriBaseId("ROOTPATH")).
		WithRegion(region)
	result := sarif.NewRuleResult(data.vulnerabilityId).
		WithRuleIndex(data.resultIndex).
		WithMessage(message).
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

	ruleIndexes := map[string]int{}

	for _, res := range report.Results {
		for _, vuln := range res.Vulnerabilities {
			sw.addSarifResult(&sarifData{
				caption:          "Vulnerability",
				vulnerabilityId:  vuln.VulnerabilityID,
				title:            vuln.Title,
				description:      vuln.Description,
				severity:         vuln.Severity,
				pkgName:          vuln.PkgName,
				fixedVersion:     vuln.FixedVersion,
				installedVersion: vuln.InstalledVersion,
				url:              vuln.PrimaryURL,
				resourceType:     res.Type,
				filePath:         toPathUri(res.Target),
				resultIndex:      getRuleIndex(vuln.VulnerabilityID, ruleIndexes),
			})
		}
		for _, misconf := range res.Misconfigurations {
			sw.addSarifResult(&sarifData{
				caption:         "Misconfiguration",
				vulnerabilityId: misconf.ID,
				title:           misconf.Title,
				description:     misconf.Description,
				severity:        misconf.Severity,
				pkgName:         res.Type,
				url:             misconf.PrimaryURL,
				resourceType:    misconf.Type,
				filePath:        toPathUri(res.Target),
				resultIndex:     getRuleIndex(misconf.ID, ruleIndexes),
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

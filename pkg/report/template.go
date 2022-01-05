package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"os"
	"regexp"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"golang.org/x/xerrors"

	"github.com/aquasecurity/trivy-db/pkg/vulnsrc/vulnerability"
)

// regex to extract file path in case string includes (distro:version)
var re = regexp.MustCompile(`(?P<path>.+?)(?:\s*\((?:.*?)\).*?)?$`)

// TemplateWriter write result in custom format defined by user's template
type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

// NewTemplateWriter is the factory method to return TemplateWriter object
func NewTemplateWriter(output io.Writer, outputTemplate string) (*TemplateWriter, error) {
	if strings.HasPrefix(outputTemplate, "@") {
		buf, err := os.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
		if err != nil {
			return nil, xerrors.Errorf("error retrieving template from path: %w", err)
		}
		outputTemplate = string(buf)
	}
	var templateFuncMap template.FuncMap
	templateFuncMap = sprig.GenericFuncMap()
	templateFuncMap["escapeXML"] = func(input string) string {
		escaped := &bytes.Buffer{}
		if err := xml.EscapeText(escaped, []byte(input)); err != nil {
			fmt.Printf("error while escapeString to XML: %v", err.Error())
			return input
		}
		return escaped.String()
	}
	templateFuncMap["makeRuleMap"] = func() map[string]int {
		return make(map[string]int)
	}
	templateFuncMap["indexRule"] = func(rules map[string]int, vulnerabilityID string) bool {
		if _, ok := rules[vulnerabilityID]; !ok {
			rules[vulnerabilityID] = len(rules)
			return true
		}
		return false
	}
	templateFuncMap["toSarifErrorLevel"] = toSarifErrorLevel
	templateFuncMap["toSarifRuleName"] = toSarifRuleName
	templateFuncMap["endWithPeriod"] = func(input string) string {
		if !strings.HasSuffix(input, ".") {
			input += "."
		}
		return input
	}
	templateFuncMap["toLower"] = func(input string) string {
		return strings.ToLower(input)
	}
	templateFuncMap["escapeString"] = func(input string) string {
		return html.EscapeString(input)
	}
	templateFuncMap["toPathUri"] = func(input string) string {
		var matches = re.FindStringSubmatch(input)
		if matches != nil {
			input = matches[re.SubexpIndex("path")]
		}
		input = strings.ReplaceAll(input, "\\", "/")
		return input
	}
	templateFuncMap["getEnv"] = func(key string) string {
		return os.Getenv(key)
	}
	templateFuncMap["getCurrentTime"] = func() string {
		return Now().UTC().Format(time.RFC3339Nano)
	}
	tmpl, err := template.New("output template").Funcs(templateFuncMap).Parse(outputTemplate)
	if err != nil {
		return nil, xerrors.Errorf("error parsing template: %w", err)
	}
	return &TemplateWriter{Output: output, Template: tmpl}, nil
}

// Write writes result
func (tw TemplateWriter) Write(report Report) error {
	err := tw.Template.Execute(tw.Output, report.Results)
	if err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}
	return nil
}

func toSarifRuleName(vulnerabilityType string) string {
	switch vulnerabilityType {
	case vulnerability.Ubuntu, vulnerability.Alpine, vulnerability.RedHat, vulnerability.RedHatOVAL,
		vulnerability.Debian, vulnerability.DebianOVAL, vulnerability.Fedora, vulnerability.Amazon,
		vulnerability.OracleOVAL, vulnerability.SuseCVRF, vulnerability.OpenSuseCVRF, vulnerability.Photon,
		vulnerability.CentOS, vulnerability.Alma:
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

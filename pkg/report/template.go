package report

import (
	"bytes"
	"encoding/xml"
	"fmt"
	"html"
	"io"
	"os"
	"strings"
	"text/template"
	"time"

	"github.com/Masterminds/sprig"
	"golang.org/x/xerrors"
)

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

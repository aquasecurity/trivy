package report

import (
	"bytes"
	"context"
	"encoding/xml"
	"html"
	"io"
	"os"
	"strings"
	"text/template"

	"github.com/Masterminds/sprig/v3"
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/types"
)

// CustomTemplateFuncMap is used to overwrite existing functions for testing.
var CustomTemplateFuncMap = make(map[string]any)

// TemplateWriter write result in custom format defined by user's template
type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

// NewTemplateWriter is the factory method to return TemplateWriter object
func NewTemplateWriter(output io.Writer, outputTemplate, appVersion string) (*TemplateWriter, error) {
	if strings.HasPrefix(outputTemplate, "@") {
		buf, err := os.ReadFile(strings.TrimPrefix(outputTemplate, "@"))
		if err != nil {
			return nil, xerrors.Errorf("error retrieving template from path: %w", err)
		}
		outputTemplate = string(buf)
	}
	var templateFuncMap template.FuncMap = sprig.GenericFuncMap()
	templateFuncMap["escapeXML"] = func(input string) string {
		escaped := &bytes.Buffer{}
		if err := xml.EscapeText(escaped, []byte(input)); err != nil {
			log.Error("Error while escapeString to XML", log.Err(err))
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
	templateFuncMap["escapeString"] = html.EscapeString
	templateFuncMap["sourceID"] = func(input string) dbTypes.SourceID {
		return dbTypes.SourceID(input)
	}
	templateFuncMap["appVersion"] = func() string {
		return appVersion
	}

	// Overwrite functions
	for k, v := range CustomTemplateFuncMap {
		templateFuncMap[k] = v
	}

	tmpl, err := template.New("output template").Funcs(templateFuncMap).Parse(outputTemplate)
	if err != nil {
		return nil, xerrors.Errorf("error parsing template: %w", err)
	}
	return &TemplateWriter{
		Output:   output,
		Template: tmpl,
	}, nil
}

// Write writes result
func (tw TemplateWriter) Write(ctx context.Context, report types.Report) error {
	err := tw.Template.Execute(tw.Output, report.Results)
	if err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}
	return nil
}

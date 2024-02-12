package report

import (
	"io"
	"text/template"

	"github.com/deepfactor-io/trivy/pkg/types"
)

// CustomTemplateFuncMap is used to overwrite existing functions for testing.
var CustomTemplateFuncMap = make(map[string]interface{})

// TemplateWriter write result in custom format defined by user's template
type TemplateWriter struct {
	Output   io.Writer
	Template *template.Template
}

// NewTemplateWriter is the factory method to return TemplateWriter object
func NewTemplateWriter(output io.Writer, outputTemplate, appVersion string) (*TemplateWriter, error) {
	return nil, nil
}

// Write writes result
func (tw TemplateWriter) Write(report types.Report) error {
	return nil
}

package report

import (
	"io"

	"golang.org/x/xerrors"

	reportPkg "github.com/aquasecurity/trivy/pkg/report"
)

// TemplateWriter renders the Kubernetes scan report using a user-provided Go
// template. It reuses the generic report template engine so that the same
// template helpers (sprig functions, escapeXML, appVersion, ...) and the
// "@path/to/template.tpl" file reference syntax are available regardless of
// whether the scan targets a single artifact or a cluster.
type TemplateWriter struct {
	Output   io.Writer
	Report   string
	Template string
	Version  string
}

// Write writes the results using the user-defined template.
func (tw TemplateWriter) Write(report Report) error {
	writer, err := reportPkg.NewTemplateWriter(tw.Output, tw.Template, tw.Version)
	if err != nil {
		return xerrors.Errorf("failed to initialize template writer: %w", err)
	}

	// Mirror the JSON writer's report selection so "all" exposes the full
	// per-resource report and "summary" exposes the consolidated findings.
	var data any
	switch tw.Report {
	case AllReport:
		data = report
	case SummaryReport:
		data = report.consolidate()
	default:
		return xerrors.Errorf(`report %q not supported. Use "summary" or "all"`, tw.Report)
	}

	if err := writer.Template.Execute(tw.Output, data); err != nil {
		return xerrors.Errorf("failed to write with template: %w", err)
	}

	return nil
}

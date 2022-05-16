package k8s

import (
	"fmt"
	"io"

	"golang.org/x/xerrors"

	ftypes "github.com/aquasecurity/fanal/types"
	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"

	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	allReport     = "all"
	summaryReport = "summary"

	tableFormat = "table"
	jsonFormat  = "json"
)

type Option struct {
	Format     string
	Report     string
	Output     io.Writer
	Severities []dbTypes.Severity
}

// Report represents a kubernetes scan report
type Report struct {
	SchemaVersion     int `json:",omitempty"`
	ClusterName       string
	Vulnerabilities   []Resource `json:",omitempty"`
	Misconfigurations []Resource `json:",omitempty"`
}

// ConsolidatedReport represents a kubernetes scan report with consolidated findings
type ConsolidatedReport struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Findings      []Resource `json:",omitempty"`
}

// Resource represents a kubernetes resource report
type Resource struct {
	Namespace string `json:",omitempty"`
	Kind      string
	Name      string
	// TODO(josedonizetti): should add metadata? per report? per Result?
	// Metadata  Metadata `json:",omitempty"`
	Results types.Results `json:",omitempty"`
	Error   string        `json:",omitempty"`

	// original report
	Report types.Report `json:"-"`
}

// Failed returns whether the k8s report includes any vulnerabilities or misconfigurations
func (r Report) Failed() bool {
	for _, r := range r.Vulnerabilities {
		if r.Results.Failed() {
			return true
		}
	}

	for _, r := range r.Misconfigurations {
		if r.Results.Failed() {
			return true
		}
	}

	return false
}

func (r Report) consolidate() ConsolidatedReport {
	consolidated := ConsolidatedReport{
		SchemaVersion: r.SchemaVersion,
		ClusterName:   r.ClusterName,
	}

	for _, m := range r.Misconfigurations {
		found := false
		for _, v := range r.Vulnerabilities {
			if v.Kind == m.Kind && v.Name == m.Name && v.Namespace == m.Namespace {
				consolidated.Findings = append(consolidated.Findings, Resource{
					Namespace: v.Namespace,
					Kind:      v.Kind,
					Name:      v.Name,
					Results:   append(v.Results, m.Results...),
					Error:     v.Error,
				})
				found = true
				continue
			}
		}
		if !found {
			consolidated.Findings = append(consolidated.Findings, m)
		}
	}
	return consolidated
}

// Writer defines the result write operation
type Writer interface {
	Write(Report) error
}

// write writes the results in the give format
func write(report Report, option Option) error {
	var writer Writer
	switch option.Format {
	case jsonFormat:
		writer = &JSONWriter{Output: option.Output, Report: option.Report}
	case tableFormat:
		writer = &TableWriter{
			Output:     option.Output,
			Report:     option.Report,
			Severities: option.Severities,
		}
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	return writer.Write(report)
}

func createResource(artifact *artifacts.Artifact, report types.Report, err error) Resource {
	results := make([]types.Result, 0, len(report.Results))
	// fix target name
	for _, result := range report.Results {
		// if resource is a kubernetes file fix the target name,
		// to avoid showing the temp file that was removed.
		if result.Type == ftypes.Kubernetes {
			result.Target = fmt.Sprintf("%s/%s", artifact.Kind, artifact.Name)
		}
		results = append(results, result)
	}

	r := Resource{
		Namespace: artifact.Namespace,
		Kind:      artifact.Kind,
		Name:      artifact.Name,
		Results:   results,
		Report:    report,
	}

	// if there was any error during the scan
	if err != nil {
		r.Error = err.Error()
	}

	return r
}

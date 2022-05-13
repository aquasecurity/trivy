package k8s

import (
	"golang.org/x/xerrors"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"

	"github.com/aquasecurity/trivy/pkg/report"
	"github.com/aquasecurity/trivy/pkg/types"
)

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

// Write writes the results in the give format
func Write(report Report, option report.Option, severities []dbTypes.Severity) error {
	var writer Writer
	switch option.Format {
	case "all":
		writer = &JSONWriter{Output: option.Output}
	case "summary":
		writer = NewSummaryWriter(option.Output, severities)
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	return writer.Write(report)
}

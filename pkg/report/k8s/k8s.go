package k8s

import (
	"golang.org/x/xerrors"

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

// Resource represents a kubernetes resource report
type Resource struct {
	Namespace string `json:",omitempty"`
	Kind      string
	Name      string
	//TODO(josedonizetti): should add metadata? per report? per Result?
	//Metadata  Metadata `json:",omitempty"`
	Results types.Results `json:",omitempty"`
	Error   string        `json:",omitempty"`
}

// Failed returns whether the k8s report includes any vulnerabilities or misconfigurations
func (report Report) Failed() bool {
	for _, r := range report.Vulnerabilities {
		if r.Results.Failed() {
			return true
		}
	}

	for _, r := range report.Misconfigurations {
		if r.Results.Failed() {
			return true
		}
	}

	return false
}

// Writer defines the result write operation
type Writer interface {
	Write(Report) error
}

// Write writes the results in the give format
func Write(report Report, option report.Option) error {
	var writer Writer
	switch option.Format {
	case "json":
		writer = &JSONWriter{Output: option.Output}
	default:
		return xerrors.Errorf("unknown format: %v", option.Format)
	}

	return writer.Write(report)
}

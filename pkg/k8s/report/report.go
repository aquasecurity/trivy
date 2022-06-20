package report

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/exp/slices"

	"golang.org/x/exp/maps"
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
	Format        string
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
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

func (r Resource) fullname() string {
	return strings.ToLower(fmt.Sprintf("%s/%s/%s", r.Namespace, r.Kind, r.Name))
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

	index := make(map[string]Resource)

	for _, m := range r.Misconfigurations {
		index[m.fullname()] = m
	}

	for _, v := range r.Vulnerabilities {
		key := v.fullname()

		if r, ok := index[key]; ok {
			index[key] = Resource{
				Namespace: r.Namespace,
				Kind:      r.Kind,
				Name:      r.Name,
				Results:   append(r.Results, v.Results...),
				Error:     r.Error,
			}

			continue
		}

		index[key] = v
	}

	consolidated.Findings = maps.Values(index)

	return consolidated
}

// Writer defines the result write operation
type Writer interface {
	Write(Report) error
}

// Write writes the results in the give format
func Write(report Report, option Option, securityChecks []string) error {
	switch option.Format {
	case jsonFormat:
		jwriter := JSONWriter{Output: option.Output, Report: option.Report}
		return jwriter.Write(report)
	case tableFormat:
		workloadReport, rbacReport := separateMisConfigRoleAssessment(report, securityChecks)
		WorkloadWriter := &TableWriter{
			Output:        option.Output,
			Report:        option.Report,
			Severities:    option.Severities,
			ColumnHeading: ColumnHeading(securityChecks, WorkloadColumns()),
		}
		err := WorkloadWriter.Write(workloadReport)
		if err != nil {
			return err
		}
		rbacWriter := &TableWriter{
			Output:        option.Output,
			Report:        option.Report,
			Severities:    option.Severities,
			ColumnHeading: ColumnHeading(securityChecks, RoleColumns()),
		}
		return rbacWriter.Write(rbacReport)
	default:
		return xerrors.Errorf(`unknown format %q. Use "json" or "table"`, option.Format)
	}
}

func separateMisConfigRoleAssessment(k8sReport Report, securityChecks []string) (Report, Report) {
	workloadMisconfig := make([]Resource, 0)
	rbacAssessment := make([]Resource, 0)
	for _, misConfig := range k8sReport.Misconfigurations {
		if slices.Contains(securityChecks, types.SecurityCheckRbac) && rbacResource(misConfig) {
			rbacAssessment = append(rbacAssessment, misConfig)
		} else {
			if slices.Contains(securityChecks, types.SecurityCheckConfig) && !rbacResource(misConfig) {
				workloadMisconfig = append(workloadMisconfig, misConfig)
			}
		}
	}
	return Report{
			SchemaVersion:     0,
			ClusterName:       k8sReport.ClusterName,
			Vulnerabilities:   k8sReport.Vulnerabilities,
			Misconfigurations: workloadMisconfig,
		}, Report{
			SchemaVersion:     0,
			ClusterName:       k8sReport.ClusterName,
			Misconfigurations: rbacAssessment,
		}
}

func rbacResource(misConfig Resource) bool {
	return misConfig.Kind == "Role" || misConfig.Kind == "RoleBinding" || misConfig.Kind == "ClusterRole" || misConfig.Kind == "ClusterRoleBinding"
}

func CreateResource(artifact *artifacts.Artifact, report types.Report, err error) Resource {
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

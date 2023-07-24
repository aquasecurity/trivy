package report

import (
	"fmt"
	"io"
	"strings"

	"golang.org/x/exp/maps"
	"golang.org/x/exp/slices"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/cyclonedx/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	AllReport     = "all"
	SummaryReport = "summary"

	workloadComponent = "workload"
	infraComponent    = "infra"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
	Scanners      types.Scanners
	Components    []string
	APIVersion    string
}

// Report represents a kubernetes scan report
type Report struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Resources     []Resource      `json:",omitempty"`
	RootComponent *core.Component `json:"-"`
	name          string
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
	for _, v := range r.Resources {
		if v.Results.Failed() {
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
	vulnerabilities := make([]Resource, 0)
	for _, m := range r.Resources {
		if vulnerabilitiesOrSecretResource(m) {
			vulnerabilities = append(vulnerabilities, m)
		} else {
			index[m.fullname()] = m
		}
	}

	for _, v := range vulnerabilities {
		key := v.fullname()

		if res, ok := index[key]; ok {
			index[key] = Resource{
				Namespace: res.Namespace,
				Kind:      res.Kind,
				Name:      res.Name,
				Results:   append(res.Results, v.Results...),
				Error:     res.Error,
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

type reports struct {
	Report  Report
	Columns []string
}

// SeparateMisconfigReports returns 3 reports based on scanners and components flags,
// - misconfiguration report
// - rbac report
// - infra checks report
func SeparateMisconfigReports(k8sReport Report, scanners types.Scanners, components []string) []reports {

	workloadMisconfig := make([]Resource, 0)
	infraMisconfig := make([]Resource, 0)
	rbacAssessment := make([]Resource, 0)
	workloadVulnerabilities := make([]Resource, 0)
	workloadResource := make([]Resource, 0)
	for _, resource := range k8sReport.Resources {
		if vulnerabilitiesOrSecretResource(resource) {
			workloadVulnerabilities = append(workloadVulnerabilities, resource)
			continue
		}

		switch {
		case scanners.Enabled(types.RBACScanner) && rbacResource(resource):
			rbacAssessment = append(rbacAssessment, resource)
		case infraResource(resource):
			workload, infra := splitInfraAndWorkloadResources(resource)

			if slices.Contains(components, infraComponent) {
				infraMisconfig = append(infraMisconfig, infra)
			}

			if slices.Contains(components, workloadComponent) {
				workloadMisconfig = append(workloadMisconfig, workload)
			}

		case scanners.Enabled(types.MisconfigScanner) && !rbacResource(resource):
			if slices.Contains(components, workloadComponent) {
				workloadMisconfig = append(workloadMisconfig, resource)
			}
		}
	}

	r := make([]reports, 0)
	workloadResource = append(workloadResource, workloadVulnerabilities...)
	workloadResource = append(workloadResource, workloadMisconfig...)
	if shouldAddWorkloadReport(scanners) {
		workloadReport := Report{
			SchemaVersion: 0,
			ClusterName:   k8sReport.ClusterName,
			Resources:     workloadResource,
			name:          "Workload Assessment",
		}

		if (slices.Contains(components, workloadComponent) &&
			len(workloadMisconfig) > 0) ||
			len(workloadVulnerabilities) > 0 {
			r = append(r, reports{
				Report:  workloadReport,
				Columns: WorkloadColumns(),
			})
		}
	}

	if scanners.Enabled(types.RBACScanner) && len(rbacAssessment) > 0 {
		r = append(r, reports{
			Report: Report{
				SchemaVersion: 0,
				ClusterName:   k8sReport.ClusterName,
				Resources:     rbacAssessment,
				name:          "RBAC Assessment",
			},
			Columns: RoleColumns(),
		})
	}

	if scanners.Enabled(types.MisconfigScanner) &&
		slices.Contains(components, infraComponent) &&
		len(infraMisconfig) > 0 {

		r = append(r, reports{
			Report: Report{
				SchemaVersion: 0,
				ClusterName:   k8sReport.ClusterName,
				Resources:     infraMisconfig,
				name:          "Infra Assessment",
			},
			Columns: InfraColumns(),
		})
	}

	return r
}

func rbacResource(misConfig Resource) bool {
	return misConfig.Kind == "Role" || misConfig.Kind == "RoleBinding" || misConfig.Kind == "ClusterRole" || misConfig.Kind == "ClusterRoleBinding"
}

func infraResource(misConfig Resource) bool {
	return (misConfig.Kind == "Pod" && misConfig.Namespace == "kube-system") || misConfig.Kind == "NodeInfo"
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

func (r Report) PrintErrors() {
	for _, resource := range r.Resources {
		if resource.Error != "" {
			log.Logger.Errorf("Error during vulnerabilities or misconfiguration scan: %s", resource.Error)
		}
	}
}

func splitInfraAndWorkloadResources(misconfig Resource) (Resource, Resource) {
	workload := copyResource(misconfig)
	infra := copyResource(misconfig)

	workloadResults := make(types.Results, 0)
	infraResults := make(types.Results, 0)

	for _, result := range misconfig.Results {
		workloadMisconfigs := make([]types.DetectedMisconfiguration, 0)
		infraMisconfigs := make([]types.DetectedMisconfiguration, 0)

		for _, m := range result.Misconfigurations {
			if strings.HasPrefix(m.ID, "KCV") {
				infraMisconfigs = append(infraMisconfigs, m)
				continue
			}

			workloadMisconfigs = append(workloadMisconfigs, m)
		}

		if len(workloadMisconfigs) > 0 {
			workloadResults = append(workloadResults, copyResult(result, workloadMisconfigs))
		}

		if len(infraMisconfigs) > 0 {
			infraResults = append(infraResults, copyResult(result, infraMisconfigs))
		}
	}

	workload.Results = workloadResults
	workload.Report.Results = workloadResults

	infra.Results = infraResults
	infra.Report.Results = infraResults

	return workload, infra
}

func copyResource(r Resource) Resource {
	return Resource{
		Namespace: r.Namespace,
		Kind:      r.Kind,
		Name:      r.Name,
		Error:     r.Error,
		Report:    r.Report,
	}
}

func copyResult(r types.Result, misconfigs []types.DetectedMisconfiguration) types.Result {
	return types.Result{
		Target:            r.Target,
		Class:             r.Class,
		Type:              r.Type,
		MisconfSummary:    r.MisconfSummary,
		Misconfigurations: misconfigs,
	}
}

func shouldAddWorkloadReport(scanners types.Scanners) bool {
	return scanners.AnyEnabled(types.MisconfigScanner, types.VulnerabilityScanner, types.SecretScanner)
}

func vulnerabilitiesOrSecretResource(resource Resource) bool {
	return len(resource.Results) > 0 && (len(resource.Results[0].Vulnerabilities) > 0 || len(resource.Results[0].Secrets) > 0)
}

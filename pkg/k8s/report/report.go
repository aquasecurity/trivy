package report

import (
	"errors"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/samber/lo"

	dbTypes "github.com/aquasecurity/trivy-db/pkg/types"
	"github.com/aquasecurity/trivy-kubernetes/pkg/artifacts"
	ftypes "github.com/aquasecurity/trivy/pkg/fanal/types"
	"github.com/aquasecurity/trivy/pkg/log"
	"github.com/aquasecurity/trivy/pkg/sbom/core"
	"github.com/aquasecurity/trivy/pkg/types"
)

const (
	AllReport     = "all"
	SummaryReport = "summary"

	workloadComponent = "workload"
	infraComponent    = "infra"
	infraNamespace    = "kube-system"
)

type Option struct {
	Format        types.Format
	Report        string
	Output        io.Writer
	Severities    []dbTypes.Severity
	ColumnHeading []string
	Scanners      types.Scanners
	APIVersion    string
}

// Report represents a kubernetes scan report
type Report struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Resources     []Resource `json:",omitempty"`
	BOM           *core.BOM  `json:"-"`
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
	Metadata  []types.Metadata `json:",omitempty"`
	Results   types.Results    `json:",omitempty"`
	Error     string           `json:",omitempty"`

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
	var vulnerabilities []Resource
	for _, m := range r.Resources {
		if vulnerabilitiesOrSecretResource(m) {
			vulnerabilities = append(vulnerabilities, m)
		}
		if misconfigsResource(m) {
			res, ok := index[m.fullname()]
			index[m.fullname()] = m
			if ok {
				index[m.fullname()].Results[0].Misconfigurations = append(index[m.fullname()].Results[0].Misconfigurations, res.Results[0].Misconfigurations...)
			}
		}
	}

	for _, v := range vulnerabilities {
		key := v.fullname()

		if res, ok := index[key]; ok {
			// Combine metadata
			metadata := lo.UniqBy(append(res.Metadata, v.Metadata...), func(x types.Metadata) string {
				return x.ImageID
			})
			index[key] = Resource{
				Namespace: res.Namespace,
				Kind:      res.Kind,
				Name:      res.Name,
				Metadata:  metadata,
				Results:   append(res.Results, v.Results...),
				Error:     res.Error,
			}

			continue
		}

		index[key] = v
	}

	consolidated.Findings = lo.Values(index)

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
func SeparateMisconfigReports(k8sReport Report, scanners types.Scanners) []reports {

	var workloadMisconfig, infraMisconfig, rbacAssessment, workloadVulnerabilities, infraVulnerabilities, workloadResource []Resource
	for _, resource := range k8sReport.Resources {
		switch {
		case vulnerabilitiesOrSecretResource(resource) && !infraResource(resource):
			if resource.Namespace == infraNamespace || nodeInfoResource(resource) {
				infraVulnerabilities = append(infraVulnerabilities, nodeKind(resource))
			} else {
				workloadVulnerabilities = append(workloadVulnerabilities, resource)
			}
		case scanners.Enabled(types.RBACScanner) && rbacResource(resource):
			rbacAssessment = append(rbacAssessment, resource)
		case infraResource(resource):
			infraMisconfig = append(infraMisconfig, nodeKind(resource))
		case scanners.Enabled(types.MisconfigScanner) &&
			!rbacResource(resource):
			workloadMisconfig = append(workloadMisconfig, resource)
		}
	}

	var r []reports
	workloadResource = append(workloadResource, workloadVulnerabilities...)
	workloadResource = append(workloadResource, workloadMisconfig...)
	if shouldAddToReport(scanners) {
		workloadReport := Report{
			SchemaVersion: 0,
			ClusterName:   k8sReport.ClusterName,
			Resources:     workloadResource,
			name:          "Workload Assessment",
		}
		r = append(r, reports{
			Report:  workloadReport,
			Columns: WorkloadColumns(),
		})

	}
	infraMisconfig = append(infraMisconfig, infraVulnerabilities...)
	if shouldAddToReport(scanners) {
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

	if scanners.Enabled(types.RBACScanner) {
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

	return r
}

func rbacResource(misConfig Resource) bool {
	return slices.Contains([]string{
		"Role",
		"RoleBinding",
		"ClusterRole",
		"ClusterRoleBinding",
	}, misConfig.Kind)
}

func infraResource(misConfig Resource) bool {
	return !rbacResource(misConfig) && (misConfig.Namespace == infraNamespace) || nodeInfoResource(misConfig)
}

func CreateResource(artifact *artifacts.Artifact, report types.Report, err error) Resource {
	r := createK8sResource(artifact, report.Results)

	r.Metadata = []types.Metadata{report.Metadata}
	r.Report = report
	// if there was any error during the scan
	if err != nil {
		r.Error = err.Error()
	}

	return r
}

func nodeInfoResource(nodeInfo Resource) bool {
	return nodeInfo.Kind == "NodeInfo" || nodeInfo.Kind == "NodeComponents"
}

func createK8sResource(artifact *artifacts.Artifact, scanResults types.Results) Resource {
	results := make([]types.Result, 0, len(scanResults))
	// fix target name
	for _, result := range scanResults {
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
		Metadata:  []types.Metadata{},
		Results:   results,
		Report: types.Report{
			Results:      results,
			ArtifactName: artifact.Name,
		},
	}

	return r
}

func (r Report) PrintErrors() {
	for _, resource := range r.Resources {
		if resource.Error != "" {
			log.Error("Error during vulnerabilities or misconfiguration scan", log.Err(errors.New(resource.Error)))
		}
	}
}

func shouldAddToReport(scanners types.Scanners) bool {
	return scanners.AnyEnabled(
		types.MisconfigScanner,
		types.VulnerabilityScanner,
		types.SecretScanner)
}

func vulnerabilitiesOrSecretResource(resource Resource) bool {
	for _, result := range resource.Results {
		if len(result.Vulnerabilities) > 0 || len(resource.Results[0].Secrets) > 0 {
			return true
		}
	}
	return false
}

func misconfigsResource(resource Resource) bool {
	return len(resource.Results) > 0 && len(resource.Results[0].Misconfigurations) > 0
}

func nodeKind(resource Resource) Resource {
	if nodeInfoResource(resource) {
		resource.Kind = "Node"
	}
	return resource
}

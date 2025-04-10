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

type Report struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Resources     []Resource `json:",omitempty"`
	BOM           *core.BOM  `json:"-"`
	name          string
}

type ConsolidatedReport struct {
	SchemaVersion int `json:",omitempty"`
	ClusterName   string
	Findings      []Resource `json:",omitempty"`
}

type Resource struct {
	Namespace string `json:",omitempty"`
	Kind      string
	Name      string
	Metadata  []types.Metadata `json:",omitempty"`
	Results   types.Results    `json:",omitempty"`
	Error     string           `json:",omitempty"`
	Report    types.Report     `json:"-"`
}

func (r Resource) fullname() string {
	return strings.ToLower(fmt.Sprintf("%s/%s/%s", r.Namespace, r.Kind, r.Name))
}

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
			key := m.fullname()
			if res, ok := index[key]; ok {
				// Save the existing misconfigurations first
				existingMisconfigs := res.Results[0].Misconfigurations
				// Create a copy of the current resource
				newResource := m
				// Append the existing misconfigurations
				newResource.Results[0].Misconfigurations = append(
					newResource.Results[0].Misconfigurations,
					existingMisconfigs...)
				// Update the index
				index[key] = newResource
			} else {
				index[key] = m
			}
		}
	}

	for _, v := range vulnerabilities {
		key := v.fullname()

		if res, ok := index[key]; ok {
			metadata := lo.UniqBy(append(res.Metadata, v.Metadata...), func(x types.Metadata) string {
				return x.ImageID
			})
			index[key] = Resource{
				Namespace: res.Namespace,
				Kind:      res.Kind,
				Name:      res.Name,
				Metadata:  metadata,
				Results:   mergeResults(res.Results, v.Results),
				Error:     res.Error,
			}
			continue
		}

		index[key] = v
	}

	consolidated.Findings = lo.Values(index)

	return consolidated
}

func mergeResults(a, b types.Results) types.Results {
	resultMap := make(map[string]types.Result)

	for _, r := range append(a, b...) {
		key := fmt.Sprintf("%s|%s|%s", r.Target, r.Type, r.Class)

		if existing, ok := resultMap[key]; ok {
			existing.Vulnerabilities = append(existing.Vulnerabilities, r.Vulnerabilities...)
			existing.Misconfigurations = append(existing.Misconfigurations, r.Misconfigurations...)
			existing.Secrets = append(existing.Secrets, r.Secrets...)
			resultMap[key] = existing
		} else {
			resultMap[key] = r
		}
	}

	return lo.Values(resultMap)
}

type Writer interface {
	Write(Report) error
}

type reports struct {
	Report  Report
	Columns []string
}

func SeparateMisconfigReports(k8sReport Report, scanners types.Scanners) []reports {
	// Create maps to track unique resources by their identifier
	workloadMap := make(map[string]Resource)
	infraMap := make(map[string]Resource)
	rbacMap := make(map[string]Resource)

	for _, resource := range k8sReport.Resources {
		key := fmt.Sprintf("%s/%s/%s", resource.Namespace, resource.Kind, resource.Name)

		// Handle RBAC resources
		if scanners.Enabled(types.RBACScanner) && rbacResource(resource) {
			rbacKey := resource.fullname()
			if existing, ok := rbacMap[rbacKey]; ok {
				// Merge results if the resource already exists
				existing.Results = mergeResults(existing.Results, resource.Results)
				// Merge metadata
				existing.Metadata = lo.UniqBy(append(existing.Metadata, resource.Metadata...), func(x types.Metadata) string {
					return x.ImageID
				})
				rbacMap[rbacKey] = existing
			} else {
				// Add new RBAC resource
				rbacMap[rbacKey] = resource
			}
			continue
		}

		// Handle infrastructure resources
		if infraResource(resource) {
			resource = nodeKind(resource)
			if existing, ok := infraMap[key]; ok {
				// Merge all result types properly
				existing.Results = mergeResults(existing.Results, resource.Results)
				// Merge metadata
				existing.Metadata = lo.UniqBy(append(existing.Metadata, resource.Metadata...), func(x types.Metadata) string {
					return x.ImageID
				})
				infraMap[key] = existing
			} else {
				infraMap[key] = resource
			}
			continue
		}

		// Handle workload resources
		if existing, ok := workloadMap[key]; ok {
			// Merge all result types properly
			existing.Results = mergeResults(existing.Results, resource.Results)
			// Merge metadata
			existing.Metadata = lo.UniqBy(append(existing.Metadata, resource.Metadata...), func(x types.Metadata) string {
				return x.ImageID
			})
			workloadMap[key] = existing
		} else {
			workloadMap[key] = resource
		}
	}

	// Convert maps back to slices
	var workloadResources []Resource
	for _, res := range workloadMap {
		workloadResources = append(workloadResources, res)
	}

	var infraResources []Resource
	for _, res := range infraMap {
		infraResources = append(infraResources, res)
	}

	var rbacResources []Resource
	for _, res := range rbacMap {
		rbacResources = append(rbacResources, res)
	}

	var r []reports
	if shouldAddToReport(scanners) {
		// Check if we only have RBAC resources and RBAC scanner is enabled
		onlyRBAC := scanners.Enabled(types.RBACScanner) &&
			len(rbacResources) > 0 &&
			len(workloadResources) == 0 &&
			len(infraResources) == 0

		if onlyRBAC {
			// For RBAC-only case, only include RBAC Assessment
			r = append(r, reports{
				Report: Report{
					SchemaVersion: 0,
					ClusterName:   k8sReport.ClusterName,
					Resources:     rbacResources,
					name:          "RBAC Assessment",
				},
				Columns: RoleColumns(),
			})
		} else {
			// For all other cases, include all applicable sections
			// Always add Workload Assessment
			r = append(r, reports{
				Report: Report{
					SchemaVersion: 0,
					ClusterName:   k8sReport.ClusterName,
					Resources:     workloadResources,
					name:          "Workload Assessment",
				},
				Columns: WorkloadColumns(),
			})

			// Always add Infra Assessment
			r = append(r, reports{
				Report: Report{
					SchemaVersion: 0,
					ClusterName:   k8sReport.ClusterName,
					Resources:     infraResources,
					name:          "Infra Assessment",
				},
				Columns: InfraColumns(),
			})

			// Add RBAC Assessment if RBAC scanner is enabled
			if scanners.Enabled(types.RBACScanner) {
				r = append(r, reports{
					Report: Report{
						SchemaVersion: 0,
						ClusterName:   k8sReport.ClusterName,
						Resources:     rbacResources,
						name:          "RBAC Assessment",
					},
					Columns: RoleColumns(),
				})
			}
		}
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
	for _, result := range scanResults {
		if result.Type == ftypes.Kubernetes {
			result.Target = fmt.Sprintf("%s/%s", artifact.Kind, artifact.Name)
		}
		results = append(results, result)
	}
	return Resource{
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
		types.SecretScanner,
		types.RBACScanner,
	)
}

func vulnerabilitiesOrSecretResource(resource Resource) bool {
	for _, result := range resource.Results {
		if len(result.Vulnerabilities) > 0 || len(result.Secrets) > 0 {
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
		resource.Namespace = ""
	}
	return resource
}

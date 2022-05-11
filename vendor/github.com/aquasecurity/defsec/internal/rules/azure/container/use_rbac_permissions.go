package container

import (
	"github.com/aquasecurity/defsec/internal/rules"
	"github.com/aquasecurity/defsec/pkg/providers"
	"github.com/aquasecurity/defsec/pkg/scan"
	"github.com/aquasecurity/defsec/pkg/severity"
	"github.com/aquasecurity/defsec/pkg/state"
)

var CheckUseRbacPermissions = rules.Register(
	scan.Rule{
		AVDID:       "AVD-AZU-0042",
		Provider:    providers.AzureProvider,
		Service:     "container",
		ShortCode:   "use-rbac-permissions",
		Summary:     "Ensure RBAC is enabled on AKS clusters",
		Impact:      "No role based access control is in place for the AKS cluster",
		Resolution:  "Enable RBAC",
		Explanation: `Using Kubernetes role-based access control (RBAC), you can grant users, groups, and service accounts access to only the resources they need.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/aks/concepts-identity",
		},
		Terraform: &scan.EngineMetadata{
			GoodExamples:        terraformUseRbacPermissionsGoodExamples,
			BadExamples:         terraformUseRbacPermissionsBadExamples,
			Links:               terraformUseRbacPermissionsLinks,
			RemediationMarkdown: terraformUseRbacPermissionsRemediationMarkdown,
		},
		Severity: severity.High,
	},
	func(s *state.State) (results scan.Results) {
		for _, cluster := range s.Azure.Container.KubernetesClusters {
			if cluster.IsUnmanaged() {
				continue
			}
			if cluster.RoleBasedAccessControl.Enabled.IsFalse() {
				results.Add(
					"Cluster has RBAC disabled",
					cluster.RoleBasedAccessControl.Enabled,
				)
			} else {
				results.AddPassed(&cluster)
			}
		}
		return
	},
)

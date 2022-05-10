package synapse

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckVirtualNetworkEnabled = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AZU-0034",
		Provider:   providers.AzureProvider,
		Service:    "synapse",
		ShortCode:  "virtual-network-enabled",
		Summary:    "Synapse Workspace should have managed virtual network enabled, the default is disabled.",
		Impact:     "Your Synapse workspace is not using the private endpoints",
		Resolution: "Set manage virtual network to enabled",
		Explanation: `Synapse Workspace does not have managed virtual network enabled by default.

When you create your Azure Synapse workspace, you can choose to associate it to a Microsoft Azure Virtual Network. The Virtual Network associated with your workspace is managed by Azure Synapse. This Virtual Network is called a Managed workspace Virtual Network.
Managed private endpoints are private endpoints created in a Managed Virtual Network associated with your Azure Synapse workspace. Managed private endpoints establish a private link to Azure resources. You can only use private links in a workspace that has a Managed workspace Virtual Network.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-private-endpoints",
			"https://docs.microsoft.com/en-us/azure/synapse-analytics/security/synapse-workspace-managed-vnet",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformVirtualNetworkEnabledGoodExamples,
			BadExamples:         terraformVirtualNetworkEnabledBadExamples,
			Links:               terraformVirtualNetworkEnabledLinks,
			RemediationMarkdown: terraformVirtualNetworkEnabledRemediationMarkdown,
		},
		Severity: severity.Medium,
	},
	func(s *state.State) (results rules.Results) {
		for _, workspace := range s.Azure.Synapse.Workspaces {
			if workspace.IsUnmanaged() {
				continue
			}
			if workspace.EnableManagedVirtualNetwork.IsFalse() {
				results.Add(
					"Workspace does not have a managed virtual network enabled.",
					workspace.EnableManagedVirtualNetwork,
				)
			} else {
				results.AddPassed(&workspace)
			}
		}
		return
	},
)

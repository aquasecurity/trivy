package keyvault

import (
	"github.com/aquasecurity/defsec/providers"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/severity"
	"github.com/aquasecurity/defsec/state"
)

var CheckSpecifyNetworkAcl = rules.Register(
	rules.Rule{
		AVDID:      "AVD-AZU-0013",
		Provider:   providers.AzureProvider,
		Service:    "keyvault",
		ShortCode:  "specify-network-acl",
		Summary:    "Key vault should have the network acl block specified",
		Impact:     "Without a network ACL the key vault is freely accessible",
		Resolution: "Set a network ACL for the key vault",
		Explanation: `Network ACLs allow you to reduce your exposure to risk by limiting what can access your key vault. 

The default action of the Network ACL should be set to deny for when IPs are not matched. Azure services can be allowed to bypass.`,
		Links: []string{
			"https://docs.microsoft.com/en-us/azure/key-vault/general/network-security",
		},
		Terraform: &rules.EngineMetadata{
			GoodExamples:        terraformSpecifyNetworkAclGoodExamples,
			BadExamples:         terraformSpecifyNetworkAclBadExamples,
			Links:               terraformSpecifyNetworkAclLinks,
			RemediationMarkdown: terraformSpecifyNetworkAclRemediationMarkdown,
		},
		Severity: severity.Critical,
	},
	func(s *state.State) (results rules.Results) {
		for _, vault := range s.Azure.KeyVault.Vaults {
			if vault.IsUnmanaged() {
				continue
			}
			if vault.NetworkACLs.DefaultAction.NotEqualTo("Deny") {
				results.Add(
					"Vault network ACL does not block access by default.",
					vault.NetworkACLs.DefaultAction,
				)
			} else {
				results.AddPassed(&vault)
			}
		}
		return
	},
)

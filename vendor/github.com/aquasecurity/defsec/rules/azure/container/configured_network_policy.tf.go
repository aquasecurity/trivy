package container

var terraformConfiguredNetworkPolicyGoodExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "good_example" {
 	network_profile {
 	  network_policy = "calico"
 	  }
 }
 `,
}

var terraformConfiguredNetworkPolicyBadExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "bad_example" {
 	network_profile {
 	  }
 }
 `,
}

var terraformConfiguredNetworkPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#network_policy`,
}

var terraformConfiguredNetworkPolicyRemediationMarkdown = ``

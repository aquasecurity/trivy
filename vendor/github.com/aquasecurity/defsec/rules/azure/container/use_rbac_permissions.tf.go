package container

var terraformUseRbacPermissionsGoodExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "good_example" {
 	role_based_access_control {
 		enabled = true
 	}
 }
 `,
}

var terraformUseRbacPermissionsBadExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "bad_example" {
 	role_based_access_control {
 		enabled = false
 	}
 }
 `,
}

var terraformUseRbacPermissionsLinks = []string{
	`https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control`,
}

var terraformUseRbacPermissionsRemediationMarkdown = ``

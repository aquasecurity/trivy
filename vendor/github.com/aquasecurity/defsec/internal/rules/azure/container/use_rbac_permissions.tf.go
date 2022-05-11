package container

var terraformUseRbacPermissionsGoodExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "good_example" {
	// azurerm < 2.99.0
	role_based_access_control {
 		enabled = true
 	}

	// azurerm >= 2.99.0
 	role_based_access_control_enabled = true
 }
 `,
}

var terraformUseRbacPermissionsBadExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "bad_example" {
	// azurerm < 2.99.0
 	role_based_access_control {
 		enabled = false
 	}

	// azurerm >= 2.99.0
	role_based_access_control_enabled = false
 }
 `,
}

var terraformUseRbacPermissionsLinks = []string{
	`https://www.terraform.io/docs/providers/azurerm/r/kubernetes_cluster.html#role_based_access_control`,
}

var terraformUseRbacPermissionsRemediationMarkdown = ``

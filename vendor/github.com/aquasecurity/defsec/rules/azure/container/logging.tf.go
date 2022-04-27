package container

var terraformLoggingGoodExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "good_example" {
     addon_profile {
 		oms_agent {
 			enabled = true
 		}
 	}
 }
 `,
}

var terraformLoggingBadExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "bad_example" {
     addon_profile {}
 }
 `,
}

var terraformLoggingLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#oms_agent`,
}

var terraformLoggingRemediationMarkdown = ``

package container

var terraformLimitAuthorizedIpsGoodExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "good_example" {
     api_server_authorized_ip_ranges = [
 		"1.2.3.4/32"
 	]
 }
 `,
}

var terraformLimitAuthorizedIpsBadExamples = []string{
	`
 resource "azurerm_kubernetes_cluster" "bad_example" {
 
 }
 `,
}

var terraformLimitAuthorizedIpsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/kubernetes_cluster#api_server_authorized_ip_ranges`,
}

var terraformLimitAuthorizedIpsRemediationMarkdown = ``

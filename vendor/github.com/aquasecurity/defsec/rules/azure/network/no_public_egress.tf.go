package network

var terraformNoPublicEgressGoodExamples = []string{
	`
 resource "azurerm_network_security_rule" "good_example" {
 	direction = "Outbound"
 	destination_address_prefix = "10.0.0.0/16"
 	access = "Allow"
 }`,
}

var terraformNoPublicEgressBadExamples = []string{
	`
 resource "azurerm_network_security_rule" "bad_example" {
 	direction = "Outbound"
 	destination_address_prefix = "0.0.0.0/0"
 	access = "Allow"
 }`,
}

var terraformNoPublicEgressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule`,
}

var terraformNoPublicEgressRemediationMarkdown = ``

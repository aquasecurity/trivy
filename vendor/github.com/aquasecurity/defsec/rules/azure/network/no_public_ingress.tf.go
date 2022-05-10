package network

var terraformNoPublicIngressGoodExamples = []string{
	`
 resource "azurerm_network_security_rule" "good_example" {
 	direction = "Inbound"
 	destination_address_prefix = "10.0.0.0/16"
 	access = "Allow"
 }`,
}

var terraformNoPublicIngressBadExamples = []string{
	`
 resource "azurerm_network_security_rule" "bad_example" {
 	direction = "Inbound"
 	source_address_prefix = "0.0.0.0/0"
 	access = "Allow"
 }`,
}

var terraformNoPublicIngressLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule`,
}

var terraformNoPublicIngressRemediationMarkdown = ``

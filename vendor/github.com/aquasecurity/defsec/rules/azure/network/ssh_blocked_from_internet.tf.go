package network

var terraformSshBlockedFromInternetGoodExamples = []string{
	`
 resource "azurerm_network_security_rule" "good_example" {
      name                        = "good_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = "22"
      source_address_prefix       = "82.102.23.23"
      destination_address_prefix  = "*"
 }
 `,
}

var terraformSshBlockedFromInternetBadExamples = []string{
	`
 resource "azurerm_network_security_rule" "bad_example" {
      name                        = "bad_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_range      = "22"
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
 }
 `,
}

var terraformSshBlockedFromInternetLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule`, `https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges`,
}

var terraformSshBlockedFromInternetRemediationMarkdown = ``

package network

var terraformDisableRdpFromInternetGoodExamples = []string{
	`
 resource "azurerm_network_security_rule" "good_example" {
      name                        = "good_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "4.53.160.75"
      destination_address_prefix  = "*"
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "4.53.160.75"
      destination_address_prefix  = "*"
   }
 }
 `,
}

var terraformDisableRdpFromInternetBadExamples = []string{
	`
 resource "azurerm_network_security_rule" "bad_example" {
      name                        = "bad_example_security_rule"
      direction                   = "Inbound"
      access                      = "Allow"
      protocol                    = "TCP"
      source_port_range           = "*"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
 }
 
 resource "azurerm_network_security_group" "example" {
   name                = "tf-appsecuritygroup"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   
   security_rule {
 	 source_port_range           = "any"
      destination_port_ranges     = ["3389"]
      source_address_prefix       = "*"
      destination_address_prefix  = "*"
   }
 }
 `,
}

var terraformDisableRdpFromInternetLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/data-sources/network_security_group#security_rule`, `https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule#source_port_ranges`,
}

var terraformDisableRdpFromInternetRemediationMarkdown = ``

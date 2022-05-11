package datafactory

var terraformNoPublicAccessGoodExamples = []string{
	`
 resource "azurerm_data_factory" "good_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   public_network_enabled = false
 }
 `,
}

var terraformNoPublicAccessBadExamples = []string{
	`
 resource "azurerm_data_factory" "bad_example" {
   name                = "example"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 }
 `,
}

var terraformNoPublicAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/data_factory#public_network_enabled`,
}

var terraformNoPublicAccessRemediationMarkdown = ``

package keyvault

var terraformNoPurgeGoodExamples = []string{
	`
 resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = true
 }
 `,
}

var terraformNoPurgeBadExamples = []string{
	`
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     purge_protection_enabled    = false
 }
 `,
}

var terraformNoPurgeLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#purge_protection_enabled`,
}

var terraformNoPurgeRemediationMarkdown = ``

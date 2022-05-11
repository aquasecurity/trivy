package keyvault

var terraformSpecifyNetworkAclGoodExamples = []string{
	`
 resource "azurerm_key_vault" "good_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.good_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = false
 
     network_acls {
         bypass = "AzureServices"
         default_action = "Deny"
     }
 }
 `,
}

var terraformSpecifyNetworkAclBadExamples = []string{
	`
 resource "azurerm_key_vault" "bad_example" {
     name                        = "examplekeyvault"
     location                    = azurerm_resource_group.bad_example.location
     enabled_for_disk_encryption = true
     soft_delete_retention_days  = 7
     purge_protection_enabled    = false
 }
 `,
}

var terraformSpecifyNetworkAclLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault#network_acls`,
}

var terraformSpecifyNetworkAclRemediationMarkdown = ``

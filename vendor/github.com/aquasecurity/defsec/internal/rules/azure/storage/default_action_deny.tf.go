package storage

var terraformDefaultActionDenyGoodExamples = []string{
	`
 resource "azurerm_storage_account_network_rules" "good_example" {
   
   default_action             = "Deny"
   ip_rules                   = ["127.0.0.1"]
   virtual_network_subnet_ids = [azurerm_subnet.test.id]
   bypass                     = ["Metrics"]
 }
 `,
}

var terraformDefaultActionDenyBadExamples = []string{
	`
 resource "azurerm_storage_account_network_rules" "bad_example" {
   
   default_action             = "Allow"
   ip_rules                   = ["127.0.0.1"]
   virtual_network_subnet_ids = [azurerm_subnet.test.id]
   bypass                     = ["Metrics"]
 }
 `,
}

var terraformDefaultActionDenyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account_network_rules#default_action`,
}

var terraformDefaultActionDenyRemediationMarkdown = ``

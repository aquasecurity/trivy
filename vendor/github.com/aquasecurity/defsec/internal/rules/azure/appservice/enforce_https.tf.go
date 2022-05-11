package appservice

var terraformEnforceHttpsGoodExamples = []string{
	`
 resource "azurerm_function_app" "good_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
   https_only                 = true
 }
 `,
}

var terraformEnforceHttpsBadExamples = []string{
	`
 resource "azurerm_function_app" "bad_example" {
   name                       = "test-azure-functions"
   location                   = azurerm_resource_group.example.location
   resource_group_name        = azurerm_resource_group.example.name
   app_service_plan_id        = azurerm_app_service_plan.example.id
   storage_account_name       = azurerm_storage_account.example.name
   storage_account_access_key = azurerm_storage_account.example.primary_access_key
   os_type                    = "linux"
 }
 `,
}

var terraformEnforceHttpsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/function_app#https_only`,
}

var terraformEnforceHttpsRemediationMarkdown = ``

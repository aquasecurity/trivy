package appservice

var terraformAccountIdentityRegisteredGoodExamples = []string{
	`
 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   identity {
     type = "UserAssigned"
     identity_ids = "webapp1"
   }
 }
 `,
}

var terraformAccountIdentityRegisteredBadExamples = []string{
	`
 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 `,
}

var terraformAccountIdentityRegisteredLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#identity`,
}

var terraformAccountIdentityRegisteredRemediationMarkdown = ``

package appservice

var terraformEnableHttp2GoodExamples = []string{
	`
 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   site_config {
 	  http2_enabled = true
   }
 }
 `,
}

var terraformEnableHttp2BadExamples = []string{
	`
 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 `, `
 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
   site_config {
 	  http2_enabled = false
   }
 }
 `,
}

var terraformEnableHttp2Links = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#http2_enabled`,
}

var terraformEnableHttp2RemediationMarkdown = ``

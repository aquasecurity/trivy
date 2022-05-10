package appservice

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "azurerm_app_service" "good_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "azurerm_app_service" "bad_example" {
   name                = "example-app-service"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
   app_service_plan_id = azurerm_app_service_plan.example.id
 
   site_config {
 	  min_tls_version = "1.0"
   }
 }
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/app_service#min_tls_version`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``

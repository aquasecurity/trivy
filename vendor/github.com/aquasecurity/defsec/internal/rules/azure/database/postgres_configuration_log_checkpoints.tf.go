package database

var terraformPostgresConfigurationLogCheckpointsGoodExamples = []string{
	`
 resource "azurerm_resource_group" "example" {
   name     = "example-resources"
   location = "West Europe"
 }
 
 resource "azurerm_postgresql_server" "example" {
   name                = "example-psqlserver"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 
   administrator_login          = "psqladminun"
   administrator_login_password = "H@Sh1CoR3!"
 
   sku_name   = "GP_Gen5_4"
   version    = "9.6"
   storage_mb = 640000
 }
 
 resource "azurerm_postgresql_configuration" "example" {
   name                = "log_checkpoints"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_postgresql_server.example.name
   value               = "on"
 }
 
 `,
}

var terraformPostgresConfigurationLogCheckpointsBadExamples = []string{
	`
 resource "azurerm_resource_group" "example" {
   name     = "example-resources"
   location = "West Europe"
 }
 
 resource "azurerm_postgresql_server" "example" {
   name                = "example-psqlserver"
   location            = azurerm_resource_group.example.location
   resource_group_name = azurerm_resource_group.example.name
 
   administrator_login          = "psqladminun"
   administrator_login_password = "H@Sh1CoR3!"
 
   sku_name   = "GP_Gen5_4"
   version    = "9.6"
   storage_mb = 640000
 }
 `,
}

var terraformPostgresConfigurationLogCheckpointsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_configuration`,
}

var terraformPostgresConfigurationLogCheckpointsRemediationMarkdown = ``

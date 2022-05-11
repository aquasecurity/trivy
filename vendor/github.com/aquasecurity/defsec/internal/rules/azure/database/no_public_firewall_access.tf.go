package database

var terraformNoPublicFirewallAccessGoodExamples = []string{
	`
 resource "azurerm_sql_firewall_rule" "good_example" {
   name                = "good_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "0.0.0.0"
 }
 `,
}

var terraformNoPublicFirewallAccessBadExamples = []string{
	`
 resource "azurerm_sql_firewall_rule" "bad_example" {
   name                = "bad_rule"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_sql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 
 resource "azurerm_postgresql_firewall_rule" "bad_example" {
   name                = "bad_example"
   resource_group_name = azurerm_resource_group.example.name
   server_name         = azurerm_postgresql_server.example.name
   start_ip_address    = "0.0.0.0"
   end_ip_address      = "255.255.255.255"
 }
 `,
}

var terraformNoPublicFirewallAccessLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/sql_firewall_rule#end_ip_address`,
}

var terraformNoPublicFirewallAccessRemediationMarkdown = ``

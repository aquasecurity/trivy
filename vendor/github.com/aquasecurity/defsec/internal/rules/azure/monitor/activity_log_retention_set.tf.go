package monitor

var terraformActivityLogRetentionSetGoodExamples = []string{
	`
 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
 `,
}

var terraformActivityLogRetentionSetBadExamples = []string{
	`
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
}

var terraformActivityLogRetentionSetLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#retention_policy`,
}

var terraformActivityLogRetentionSetRemediationMarkdown = ``

package monitor

var terraformCaptureAllActivitiesGoodExamples = []string{
	`
 resource "azurerm_monitor_log_profile" "good_example" {
   name = "good_example"
 
   categories = [
 	  "Action",
 	  "Delete",
 	  "Write",
   ]
 
   retention_policy {
     enabled = true
     days    = 365
   }
 }
 `,
}

var terraformCaptureAllActivitiesBadExamples = []string{
	`
 resource "azurerm_monitor_log_profile" "bad_example" {
   name = "bad_example"
 
   categories = []
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 `,
}

var terraformCaptureAllActivitiesLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#categories`,
}

var terraformCaptureAllActivitiesRemediationMarkdown = ``

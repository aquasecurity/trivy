package securitycenter

var terraformEnableStandardSubscriptionGoodExamples = []string{
	`
 resource "azurerm_security_center_subscription_pricing" "good_example" {
   tier          = "Standard"
   resource_type = "VirtualMachines"
 }
 `,
}

var terraformEnableStandardSubscriptionBadExamples = []string{
	`
 resource "azurerm_security_center_subscription_pricing" "bad_example" {
   tier          = "Free"
   resource_type = "VirtualMachines"
 }
 `,
}

var terraformEnableStandardSubscriptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier`,
}

var terraformEnableStandardSubscriptionRemediationMarkdown = ``

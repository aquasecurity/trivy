package securitycenter

var terraformSetRequiredContactDetailsGoodExamples = []string{
	`
		resource "azurerm_security_center_contact" "good_example" {
		email = "good_contact@example.com"
		phone = "+1-555-555-5555"

		alert_notifications = true
		alerts_to_admins = true
		}
	`,
}

var terraformSetRequiredContactDetailsBadExamples = []string{
	`
		resource "azurerm_security_center_contact" "bad_example" {
		email = "bad_contact@example.com"
		phone = ""

		alert_notifications = true
		alerts_to_admins = true
		}
		`,
}

var terraformSetRequiredContactDetailsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_contact#phone`,
}

var terraformSetRequiredContactDetailsRemediationMarkdown = ``

package authorization

var terraformLimitRoleActionsGoodExamples = []string{
	`
 data "azurerm_subscription" "primary" {
 }
 
 resource "azurerm_role_definition" "example" {
   name        = "my-custom-role"
   scope       = data.azurerm_subscription.primary.id
   description = "This is a custom role created via Terraform"
 
   permissions {
     actions     = ["*"]
     not_actions = []
   }
 
   assignable_scopes = [
     data.azurerm_subscription.primary.id,
   ]
 }
 `,
}

var terraformLimitRoleActionsBadExamples = []string{
	`
 data "azurerm_subscription" "primary" {
 }
 
 resource "azurerm_role_definition" "example" {
   name        = "my-custom-role"
   scope       = data.azurerm_subscription.primary.id
   description = "This is a custom role created via Terraform"
 
   permissions {
     actions     = ["*"]
     not_actions = []
   }
 
   assignable_scopes = [
     "/"
   ]
 }
 `,
}

var terraformLimitRoleActionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/role_definition#actions`,
}

var terraformLimitRoleActionsRemediationMarkdown = ``

package keyvault

var terraformEnsureSecretExpiryGoodExamples = []string{
	`
 resource "azurerm_key_vault_secret" "good_example" {
   name            = "secret-sauce"
   value           = "szechuan"
   key_vault_id    = azurerm_key_vault.example.id
   expiration_date = "1982-12-31T00:00:00Z"
 }
 `,
	`
resource "azuread_application" "myapp" {
  display_name = "MyAzureAD App"

  group_membership_claims = ["ApplicationGroup"]
  prevent_duplicate_names = true

}

resource "azuread_application_password" "myapp" {
  application_object_id = azuread_application.myapp.object_id
}

resource "azurerm_key_vault_secret" "myapp_pass" {
  name            = "myapp-oauth"
  value           = azuread_application_password.myapp.value
  key_vault_id    = azurerm_key_vault.cluster_key_vault.id
  expiration_date = azuread_application_password.myapp.end_date
  content_type    = "Password"
}
`,
}

var terraformEnsureSecretExpiryBadExamples = []string{
	`
 resource "azurerm_key_vault_secret" "bad_example" {
   name         = "secret-sauce"
   value        = "szechuan"
   key_vault_id = azurerm_key_vault.example.id
 }
 `,
}

var terraformEnsureSecretExpiryLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_secret#expiration_date`,
}

var terraformEnsureSecretExpiryRemediationMarkdown = ``

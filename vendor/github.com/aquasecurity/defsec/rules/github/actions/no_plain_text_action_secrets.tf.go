package actions

var terraformNoPlainTextActionSecretsGoodExamples = []string{
	`
resource "github_actions_environment_secret" "good_example" {
	repository       = "my repository name"
	environment       = "my environment"
	secret_name       = "my secret name"
	encrypted_value   = var.some_encrypted_secret_string
}
`,
}

var terraformNoPlainTextActionSecretsBadExamples = []string{
	`
resource "github_actions_environment_secret" "bad_example" {	 
	repository       = "my repository name"
	environment       = "my environment"
	secret_name       = "my secret name"
	plaintext_value   = "sensitive secret string"
}
`,
}

var terraformNoPlainTextActionSecretsLinks = []string{
	`https://registry.terraform.io/providers/integrations/github/latest/docs/resources/actions_environment_secret`, `https://docs.github.com/en/actions/security-guides/security-hardening-for-github-actions`,
}

var terraformNoPlainTextActionSecretsRemediationMarkdown = ``

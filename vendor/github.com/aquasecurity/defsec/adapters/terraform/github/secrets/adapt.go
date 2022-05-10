package secrets

import (
	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/providers/github"
)

func Adapt(modules terraform.Modules) []github.EnvironmentSecret {
	return adaptSecrets(modules)
}

func adaptSecrets(modules terraform.Modules) []github.EnvironmentSecret {
	var secrets []github.EnvironmentSecret
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("github_actions_environment_secret") {
			secrets = append(secrets, adaptSecret(resource))
		}
	}
	return secrets
}

func adaptSecret(resource *terraform.Block) github.EnvironmentSecret {
	var secret github.EnvironmentSecret
	secret.Metadata = resource.GetMetadata()
	secret.SecretName = resource.GetAttribute("secret_name").AsStringValueOrDefault("", resource)
	secret.PlainTextValue = resource.GetAttribute("plaintext_value").AsStringValueOrDefault("", resource)
	secret.Environment = resource.GetAttribute("environment").AsStringValueOrDefault("", resource)
	secret.Repository = resource.GetAttribute("repository").AsStringValueOrDefault("", resource)
	secret.EncryptedValue = resource.GetAttribute("encrypted_value").AsStringValueOrDefault("", resource)
	return secret
}

package secrets

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/github"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
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
	secret := github.EnvironmentSecret{
		Metadata:       resource.GetMetadata(),
		Repository:     resource.GetAttribute("repository").AsStringValueOrDefault("", resource),
		Environment:    resource.GetAttribute("environment").AsStringValueOrDefault("", resource),
		SecretName:     resource.GetAttribute("secret_name").AsStringValueOrDefault("", resource),
		PlainTextValue: resource.GetAttribute("plaintext_value").AsStringValueOrDefault("", resource),
		EncryptedValue: resource.GetAttribute("encrypted_value").AsStringValueOrDefault("", resource),
	}
	return secret
}

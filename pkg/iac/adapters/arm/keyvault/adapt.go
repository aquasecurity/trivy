package keyvault

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/keyvault"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

func Adapt(deployment azure.Deployment) keyvault.KeyVault {
	return keyvault.KeyVault{
		Vaults: adaptVaults(deployment),
	}
}

func adaptVaults(deployment azure.Deployment) (vaults []keyvault.Vault) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.KeyVault/vaults") {
		vaults = append(vaults, adaptVault(resource, deployment))
	}

	return vaults
}

func adaptVault(resource azure.Resource, deployment azure.Deployment) keyvault.Vault {
	return keyvault.Vault{
		Metadata:                resource.Metadata,
		Secrets:                 adaptSecrets(resource, deployment),
		Keys:                    adaptKeys(resource, deployment),
		EnablePurgeProtection:   resource.Properties.GetMapValue("enablePurgeProtection").AsBoolValue(false, resource.Metadata),
		SoftDeleteRetentionDays: resource.Properties.GetMapValue("softDeleteRetentionInDays").AsIntValue(7, resource.Metadata),
		NetworkACLs: keyvault.NetworkACLs{
			Metadata:      resource.Metadata,
			DefaultAction: resource.Properties.GetMapValue("properties").GetMapValue("networkAcls").GetMapValue("defaultAction").AsStringValue("", resource.Metadata),
		},
	}
}

func adaptKeys(resource azure.Resource, deployment azure.Deployment) (keys []keyvault.Key) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.KeyVault/vaults/keys") {
		keys = append(keys, adaptKey(resource))
	}

	return keys
}

func adaptKey(resource azure.Resource) keyvault.Key {
	return keyvault.Key{
		Metadata:   resource.Metadata,
		ExpiryDate: resource.Properties.GetMapValue("attributes").GetMapValue("exp").AsTimeValue(resource.Metadata),
	}
}

func adaptSecrets(resource azure.Resource, deployment azure.Deployment) (secrets []keyvault.Secret) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.KeyVault/vaults/secrets") {
		secrets = append(secrets, adaptSecret(resource))
	}
	return secrets
}

func adaptSecret(resource azure.Resource) keyvault.Secret {
	return keyvault.Secret{
		Metadata:    resource.Metadata,
		ContentType: resource.Properties.GetMapValue("contentType").AsStringValue("", resource.Metadata),
		ExpiryDate:  resource.Properties.GetMapValue("attributes").GetMapValue("exp").AsTimeValue(resource.Metadata),
	}
}

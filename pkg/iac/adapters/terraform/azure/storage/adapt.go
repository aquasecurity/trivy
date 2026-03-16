package storage

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const minimumTlsVersionOneTwo = "TLS1_2"

func Adapt(modules terraform.Modules) storage.Storage {
	accounts, containers, networkRules := adaptAccounts(modules)

	orphanAccount := storage.Account{
		Metadata:     iacTypes.NewUnmanagedMetadata(),
		NetworkRules: adaptOrphanNetworkRules(modules, networkRules),
		EnforceHTTPS: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		Containers:   adaptOrphanContainers(modules, containers),
		QueueProperties: storage.QueueProperties{
			Metadata:      iacTypes.NewUnmanagedMetadata(),
			EnableLogging: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		},
		MinimumTLSVersion: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		BlobProperties: storage.BlobProperties{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Metadata: iacTypes.NewUnmanagedMetadata(),
				Days:     iacTypes.IntDefault(7, iacTypes.NewUnmanagedMetadata()),
			},
		},
		AccountReplicationType:          iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		InfrastructureEncryptionEnabled: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
		CustomerManagedKey: storage.CustomerManagedKey{
			Metadata:               iacTypes.NewUnmanagedMetadata(),
			KeyVaultKeyId:          iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
			UserAssignedIdentityId: iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
		},
	}

	accounts = append(accounts, orphanAccount)

	return storage.Storage{
		Accounts: accounts,
	}
}

func adaptOrphanContainers(modules terraform.Modules, containers []string) (orphans []storage.Container) {
	accountedFor := make(map[string]bool)
	for _, container := range containers {
		accountedFor[container] = true
	}
	for _, module := range modules {
		for _, containerResource := range module.GetResourcesByType("azurerm_storage_container") {
			if _, ok := accountedFor[containerResource.ID()]; ok {
				continue
			}
			orphans = append(orphans, adaptContainer(containerResource))
		}
	}

	return orphans
}

func adaptOrphanNetworkRules(modules terraform.Modules, networkRules []string) (orphans []storage.NetworkRule) {
	accountedFor := make(map[string]bool)
	for _, networkRule := range networkRules {
		accountedFor[networkRule] = true
	}

	for _, module := range modules {
		for _, networkRuleResource := range module.GetResourcesByType("azurerm_storage_account_network_rules") {
			if _, ok := accountedFor[networkRuleResource.ID()]; ok {
				continue
			}

			orphans = append(orphans, adaptNetworkRule(networkRuleResource))
		}
	}

	return orphans
}

func adaptAccounts(modules terraform.Modules) ([]storage.Account, []string, []string) {
	var accounts []storage.Account
	var accountedForContainers []string
	var accountedForNetworkRules []string

	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_storage_account") {
			account := adaptAccount(resource)
			containerResource := module.GetReferencingResources(resource, "azurerm_storage_container", "storage_account_id")

			if len(containerResource) == 0 {
				// If no referencing container resources are found, check for any containers that reference the account by Name instead of ID (older versions of the provider did this)
				containerResource = module.GetReferencingResources(resource, "azurerm_storage_container", "storage_account_name")
			}
			for _, containerBlock := range containerResource {
				accountedForContainers = append(accountedForContainers, containerBlock.ID())
				account.Containers = append(account.Containers, adaptContainer(containerBlock))
			}
			networkRulesResource := module.GetReferencingResources(resource, "azurerm_storage_account_network_rules", "storage_account_id")

			if len(networkRulesResource) == 0 {
				// If no referencing network rules resources are found, check for any that reference the account by Name instead of ID (older versions of the provider did this)
				networkRulesResource = module.GetReferencingResources(resource, "azurerm_storage_account_network_rules", "storage_account_name")
			}
			for _, networkRuleBlock := range networkRulesResource {
				accountedForNetworkRules = append(accountedForNetworkRules, networkRuleBlock.ID())
				account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkRuleBlock))
			}

			queueResource := module.GetReferencingResources(resource, "azurerm_storage_queue", "storage_account_id")

			if len(queueResource) == 0 {
				// If no referencing queue resources are found, check for any that reference the account by Name instead of ID (older versions of the provider did this)
				queueResource = module.GetReferencingResources(resource, "azurerm_storage_queue", "storage_account_name")
			}

			for _, queueBlock := range queueResource {
				queue := storage.Queue{
					Metadata: queueBlock.GetMetadata(),
					Name:     queueBlock.GetAttribute("name").AsStringValueOrDefault("", queueBlock),
				}
				account.Queues = append(account.Queues, queue)
			}
			// Adapt customer managed key resource
			// Only use the resource if the block wasn't already set (they are mutually exclusive in Terraform)
			if account.CustomerManagedKey.KeyVaultKeyId.IsEmpty() {
				customerManagedKeyResources := module.GetReferencingResources(resource, "azurerm_storage_account_customer_managed_key", "storage_account_id")
				for _, cmkResource := range customerManagedKeyResources {
					keyVaultKeyIdAttr := cmkResource.GetAttribute("key_vault_key_id")
					if keyVaultKeyIdAttr.IsNotNil() {
						account.CustomerManagedKey.KeyVaultKeyId = keyVaultKeyIdAttr.AsStringValueOrDefault("", cmkResource)
						account.CustomerManagedKey.Metadata = cmkResource.GetMetadata()
					} else {
						// If key_vault_key_id is not directly set, try to construct from key_vault_id and key_name
						keyVaultIdAttr := cmkResource.GetAttribute("key_vault_id")
						keyNameAttr := cmkResource.GetAttribute("key_name")
						if keyVaultIdAttr.IsNotNil() && keyNameAttr.IsNotNil() {
							keyVaultId := keyVaultIdAttr.AsStringValueOrDefault("", cmkResource)
							keyName := keyNameAttr.AsStringValueOrDefault("", cmkResource)
							if !keyVaultId.IsEmpty() && !keyName.IsEmpty() {
								// Construct the full key ID format: https://{keyVaultId}/keys/{keyName}
								keyId := keyVaultId.Value() + "/keys/" + keyName.Value()
								account.CustomerManagedKey.KeyVaultKeyId = iacTypes.String(keyId, cmkResource.GetMetadata())
								account.CustomerManagedKey.Metadata = cmkResource.GetMetadata()
							}
						}
					}
					userAssignedIdentityIdAttr := cmkResource.GetAttribute("user_assigned_identity_id")
					if userAssignedIdentityIdAttr.IsNotNil() {
						account.CustomerManagedKey.UserAssignedIdentityId = userAssignedIdentityIdAttr.AsStringValueOrDefault("", cmkResource)
					}
					break // Only process the first matching resource
				}
			}
			accounts = append(accounts, account)
		}
	}

	return accounts, accountedForContainers, accountedForNetworkRules
}

func adaptAccount(resource *terraform.Block) storage.Account {
	account := storage.Account{
		Metadata:     resource.GetMetadata(),
		NetworkRules: nil,
		EnforceHTTPS: iacTypes.BoolDefault(true, resource.GetMetadata()),
		Containers:   nil,
		QueueProperties: storage.QueueProperties{
			Metadata:      resource.GetMetadata(),
			EnableLogging: iacTypes.BoolDefault(false, resource.GetMetadata()),
		},
		MinimumTLSVersion:   iacTypes.StringDefault(minimumTlsVersionOneTwo, resource.GetMetadata()),
		PublicNetworkAccess: resource.GetAttribute("public_network_access_enabled").AsBoolValueOrDefault(true, resource),
		BlobProperties: storage.BlobProperties{
			Metadata: resource.GetMetadata(),
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Metadata: resource.GetMetadata(),
				Days:     iacTypes.IntDefault(7, resource.GetMetadata()),
			},
		},
		AccountReplicationType:          resource.GetAttribute("account_replication_type").AsStringValueOrDefault("", resource),
		InfrastructureEncryptionEnabled: resource.GetAttribute("infrastructure_encryption_enabled").AsBoolValueOrDefault(false, resource),
		CustomerManagedKey: storage.CustomerManagedKey{
			Metadata:               resource.GetMetadata(),
			KeyVaultKeyId:          iacTypes.StringDefault("", resource.GetMetadata()),
			UserAssignedIdentityId: iacTypes.StringDefault("", resource.GetMetadata()),
		},
	}

	networkRulesBlocks := resource.GetBlocks("network_rules")
	for _, networkBlock := range networkRulesBlocks {
		account.NetworkRules = append(account.NetworkRules, adaptNetworkRule(networkBlock))
	}

	account.EnforceHTTPS = resource.GetFirstAttributeOf(
		"enable_https_traffic_only",
		"https_traffic_only_enabled", // provider above version 4
	).AsBoolValueOrDefault(true, resource)

	// Adapt blob properties
	blobPropertiesBlock := resource.GetBlock("blob_properties")
	if blobPropertiesBlock.IsNotNil() {
		account.BlobProperties.Metadata = blobPropertiesBlock.GetMetadata()
		deleteRetentionPolicyBlock := blobPropertiesBlock.GetBlock("delete_retention_policy")
		if deleteRetentionPolicyBlock.IsNotNil() {
			account.BlobProperties.DeleteRetentionPolicy.Metadata = deleteRetentionPolicyBlock.GetMetadata()
			daysAttr := deleteRetentionPolicyBlock.GetAttribute("days")
			if daysAttr.IsNotNil() {
				account.BlobProperties.DeleteRetentionPolicy.Days = daysAttr.AsIntValueOrDefault(7, deleteRetentionPolicyBlock)
			}
		}
	}

	// Adapt customer managed key
	customerManagedKeyBlock := resource.GetBlock("customer_managed_key")
	if customerManagedKeyBlock.IsNotNil() {
		account.CustomerManagedKey.Metadata = customerManagedKeyBlock.GetMetadata()
		keyVaultKeyIdAttr := customerManagedKeyBlock.GetAttribute("key_vault_key_id")
		if keyVaultKeyIdAttr.IsNotNil() {
			account.CustomerManagedKey.KeyVaultKeyId = keyVaultKeyIdAttr.AsStringValueOrDefault("", customerManagedKeyBlock)
		}
		userAssignedIdentityIdAttr := customerManagedKeyBlock.GetAttribute("user_assigned_identity_id")
		if userAssignedIdentityIdAttr.IsNotNil() {
			account.CustomerManagedKey.UserAssignedIdentityId = userAssignedIdentityIdAttr.AsStringValueOrDefault("", customerManagedKeyBlock)
		}
	}

	// Adapt queue properties
	queuePropertiesBlock := resource.GetBlock("queue_properties")
	if queuePropertiesBlock.IsNotNil() {
		account.QueueProperties.Metadata = queuePropertiesBlock.GetMetadata()
		loggingBlock := queuePropertiesBlock.GetBlock("logging")
		if loggingBlock.IsNotNil() {
			account.QueueProperties.EnableLogging = iacTypes.Bool(true, loggingBlock.GetMetadata())
			account.QueueProperties.Logging = storage.QueueLogging{
				Metadata:            loggingBlock.GetMetadata(),
				Delete:              loggingBlock.GetAttribute("delete").AsBoolValueOrDefault(false, loggingBlock),
				Read:                loggingBlock.GetAttribute("read").AsBoolValueOrDefault(false, loggingBlock),
				Write:               loggingBlock.GetAttribute("write").AsBoolValueOrDefault(false, loggingBlock),
				Version:             loggingBlock.GetAttribute("version").AsStringValueOrDefault("", loggingBlock),
				RetentionPolicyDays: loggingBlock.GetAttribute("retention_policy_days").AsIntValueOrDefault(0, loggingBlock),
			}
		}
	}

	minTLSVersionAttr := resource.GetAttribute("min_tls_version")
	account.MinimumTLSVersion = minTLSVersionAttr.AsStringValueOrDefault(minimumTlsVersionOneTwo, resource)
	return account
}

func adaptContainer(resource *terraform.Block) storage.Container {
	accessTypeAttr := resource.GetAttribute("container_access_type")
	publicAccess := iacTypes.StringDefault(storage.PublicAccessOff, resource.GetMetadata())

	if accessTypeAttr.Equals("blob") {
		publicAccess = iacTypes.String(storage.PublicAccessBlob, accessTypeAttr.GetMetadata())
	} else if accessTypeAttr.Equals("container") {
		publicAccess = iacTypes.String(storage.PublicAccessContainer, accessTypeAttr.GetMetadata())
	}

	return storage.Container{
		Metadata:     resource.GetMetadata(),
		PublicAccess: publicAccess,
	}
}

func adaptNetworkRule(resource *terraform.Block) storage.NetworkRule {
	var allowByDefault iacTypes.BoolValue
	var bypass []iacTypes.StringValue

	defaultActionAttr := resource.GetAttribute("default_action")

	if defaultActionAttr.IsNotNil() {
		allowByDefault = iacTypes.Bool(defaultActionAttr.Equals("Allow", terraform.IgnoreCase), defaultActionAttr.GetMetadata())
	} else {
		allowByDefault = iacTypes.BoolDefault(false, resource.GetMetadata())
	}

	if bypassAttr := resource.GetAttribute("bypass"); bypassAttr.IsNotNil() {
		bypass = bypassAttr.AsStringValues()
	}

	return storage.NetworkRule{
		Metadata:       resource.GetMetadata(),
		Bypass:         bypass,
		AllowByDefault: allowByDefault,
	}
}

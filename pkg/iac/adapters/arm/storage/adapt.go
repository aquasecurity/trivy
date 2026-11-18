package storage

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

const (
	accountType   = "Microsoft.Storage/storageAccounts"
	containerType = "blobServices/containers"
	queueType     = "queueServices/queues"
)

func Adapt(deployment azure.Deployment) storage.Storage {
	return storage.Storage{
		Accounts: adaptAccounts(deployment),
	}
}

func adaptAccounts(deployment azure.Deployment) []storage.Account {
	var accounts []storage.Account
	for _, resource := range deployment.GetResourcesByType(accountType) {
		account := storage.Account{
			Metadata:     resource.Metadata,
			NetworkRules: xslices.ZeroToNil(adaptNetworkRules(resource)),
			// The default value is true since API version 2019-04-01.
			EnforceHTTPS: resource.Properties.GetMapValue("supportsHttpsTrafficOnly").AsBoolValue(true, resource.Properties.GetMetadata()),
			Containers:   adaptContainers(deployment.GetChildResources(resource, containerType)),
			QueueProperties: storage.QueueProperties{
				Metadata:      resource.Properties.GetMetadata(),
				EnableLogging: types.BoolDefault(false, resource.Properties.GetMetadata()),
			},
			// The default interpretation is TLS 1.0 for this property.
			MinimumTLSVersion: resource.Properties.GetMapValue("minimumTlsVersion").
				AsStringValue("TLS1_0", resource.Properties.GetMetadata()),
			Queues: adaptQueues(deployment.GetChildResources(resource, queueType)),
			BlobProperties: storage.BlobProperties{
				Metadata: resource.Properties.GetMetadata(),
				DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
					Metadata: resource.Properties.GetMetadata(),
					Days:     resource.Properties.GetMapValue("blobServices").GetMapValue("properties").GetMapValue("deleteRetentionPolicy").GetMapValue("days").AsIntValue(0, resource.Properties.GetMetadata()),
				},
			},
			AccountReplicationType:          resource.Properties.GetMapValue("sku").GetMapValue("name").AsStringValue("", resource.Properties.GetMetadata()),
			InfrastructureEncryptionEnabled: resource.Properties.GetMapValue("encryption").GetMapValue("requireInfrastructureEncryption").AsBoolValue(false, resource.Properties.GetMetadata()),
			CustomerManagedKey: storage.CustomerManagedKey{
				Metadata:               resource.Properties.GetMetadata(),
				KeyVaultKeyId:          resource.Properties.GetMapValue("encryption").GetMapValue("keyVaultProperties").GetMapValue("keyUri").AsStringValue("", resource.Properties.GetMetadata()),
				UserAssignedIdentityId: resource.Properties.GetMapValue("encryption").GetMapValue("identity").GetMapValue("userAssignedIdentity").AsStringValue("", resource.Properties.GetMetadata()),
			},
		}

		// Adapt queue properties logging
		queueServiceLogging := resource.Properties.GetMapValue("queueServices").GetMapValue("properties").GetMapValue("logging")
		if !queueServiceLogging.IsNull() {
			account.QueueProperties.Logging = storage.QueueLogging{
				Metadata:            queueServiceLogging.GetMetadata(),
				Delete:              queueServiceLogging.GetMapValue("delete").AsBoolValue(false, queueServiceLogging.GetMetadata()),
				Read:                queueServiceLogging.GetMapValue("read").AsBoolValue(false, queueServiceLogging.GetMetadata()),
				Write:               queueServiceLogging.GetMapValue("write").AsBoolValue(false, queueServiceLogging.GetMetadata()),
				Version:             queueServiceLogging.GetMapValue("version").AsStringValue("", queueServiceLogging.GetMetadata()),
				RetentionPolicyDays: queueServiceLogging.GetMapValue("retentionPolicy").GetMapValue("days").AsIntValue(0, queueServiceLogging.GetMetadata()),
			}
			if account.QueueProperties.Logging.Delete.IsTrue() || account.QueueProperties.Logging.Read.IsTrue() || account.QueueProperties.Logging.Write.IsTrue() {
				account.QueueProperties.EnableLogging = types.Bool(true, queueServiceLogging.GetMetadata())
			}
		}

		publicNetworkAccess := resource.Properties.GetMapValue("publicNetworkAccess")
		account.PublicNetworkAccess = types.Bool(
			publicNetworkAccess.AsStringValue("Enabled", publicNetworkAccess.GetMetadata()).EqualTo("Enabled"),
			publicNetworkAccess.GetMetadata(),
		)
		accounts = append(accounts, account)
	}

	orphanContainers := deployment.GetOrphanResources(accountType, containerType)
	orphanQueues := deployment.GetOrphanResources(accountType, queueType)
	if len(orphanContainers) > 0 || len(orphanQueues) > 0 {
		accounts = append(accounts, orphanAccount(adaptContainers(orphanContainers), adaptQueues(orphanQueues)))
	}
	return accounts
}

// orphanAccount holds the containers and queues whose account is unknown.
func orphanAccount(containers []storage.Container, queues []storage.Queue) storage.Account {
	metadata := types.NewUnmanagedMetadata()
	return storage.Account{
		Metadata:     metadata,
		EnforceHTTPS: types.BoolDefault(true, metadata),
		Containers:   containers,
		QueueProperties: storage.QueueProperties{
			Metadata:      metadata,
			EnableLogging: types.BoolDefault(false, metadata),
		},
		MinimumTLSVersion:   types.StringDefault("", metadata),
		Queues:              queues,
		PublicNetworkAccess: types.BoolDefault(false, metadata),
		BlobProperties: storage.BlobProperties{
			Metadata: metadata,
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Metadata: metadata,
				Days:     types.IntDefault(0, metadata),
			},
		},
		AccountReplicationType:          types.StringDefault("", metadata),
		InfrastructureEncryptionEnabled: types.BoolDefault(false, metadata),
		CustomerManagedKey: storage.CustomerManagedKey{
			Metadata:               metadata,
			KeyVaultKeyId:          types.StringDefault("", metadata),
			UserAssignedIdentityId: types.StringDefault("", metadata),
		},
	}
}

func adaptQueues(resources []azure.Resource) []storage.Queue {
	var queues []storage.Queue
	for _, resource := range resources {
		queues = append(queues, storage.Queue{
			Metadata: resource.Metadata,
			Name:     resource.Name.AsStringValue("", resource.Metadata),
		})
	}
	return queues
}

func adaptContainers(resources []azure.Resource) []storage.Container {
	var containers []storage.Container
	for _, resource := range resources {
		containers = append(containers, adaptContainer(resource))
	}
	return containers
}

// adaptContainer maps the ARM publicAccess values None, Blob and Container to
// the values the checks expect.
// https://learn.microsoft.com/en-us/azure/templates/microsoft.storage/storageaccounts/blobservices/containers?pivots=deployment-language-arm-template
func adaptContainer(resource azure.Resource) storage.Container {
	access := resource.Properties.GetMapValue("publicAccess")
	publicAccess := types.StringDefault(storage.PublicAccessOff, resource.Metadata)
	switch value := access.AsString(); {
	case strings.EqualFold(value, "Blob"):
		publicAccess = types.String(storage.PublicAccessBlob, access.GetMetadata())
	case strings.EqualFold(value, "Container"):
		publicAccess = types.String(storage.PublicAccessContainer, access.GetMetadata())
	case strings.EqualFold(value, "None"):
		publicAccess = types.String(storage.PublicAccessOff, access.GetMetadata())
	}
	return storage.Container{
		Metadata:     resource.Metadata,
		PublicAccess: publicAccess,
	}
}

func adaptNetworkRules(resource azure.Resource) []storage.NetworkRule {
	defaultBypasses := []types.StringValue{types.StringDefault("AzureServices", resource.Metadata)}
	acl := resource.Properties.GetMapValue("networkAcls")
	if acl.IsNull() {
		// default network rule
		return []storage.NetworkRule{{
			Metadata:       resource.Metadata,
			Bypass:         defaultBypasses,
			AllowByDefault: types.BoolDefault(true, resource.Metadata),
		}}
	}

	bypassProp := acl.GetMapValue("bypass")
	bypassVal := bypassProp.AsString()

	var bypasses []types.StringValue
	if bypassVal != "" {
		// Possible values are any combination of Logging|Metrics|AzureServices (For example, "Logging, Metrics")
		// See https://github.com/Azure/azure-resource-manager-schemas/blob/0cb6180c9646c91ca212de0e59568c00ee3a47ec/schemas/2021-01-01/Microsoft.Storage.json#L2379
		for bypass := range strings.SplitSeq(bypassVal, ",") {
			bypasses = append(bypasses, types.String(strings.TrimSpace(bypass), bypassProp.GetMetadata()))
		}
	} else {
		bypasses = defaultBypasses
	}

	allowByDefault := types.Bool(true, acl.GetMetadata())
	if defaultAction := acl.GetMapValue("defaultAction"); !defaultAction.IsNull() {
		allowByDefault = types.Bool(defaultAction.EqualTo("Allow"), defaultAction.GetMetadata())
	}

	return []storage.NetworkRule{{
		Metadata:       acl.GetMetadata(),
		Bypass:         bypasses,
		AllowByDefault: allowByDefault,
	}}
}

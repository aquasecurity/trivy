package storage

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

const containerType = "Microsoft.Storage/storageAccounts/blobServices/containers"

func Adapt(deployment azure.Deployment) storage.Storage {
	return storage.Storage{
		Accounts: adaptAccounts(deployment),
	}
}

func adaptAccounts(deployment azure.Deployment) []storage.Account {
	var accounts []storage.Account
	for _, resource := range deployment.GetResourcesByType("Microsoft.Storage/storageAccounts") {

		var queues []storage.Queue
		for _, queueResource := range resource.GetResourcesByType("queueServices/queues") {
			queues = append(queues, storage.Queue{
				Metadata: queueResource.Metadata,
				Name:     queueResource.Name.AsStringValue("", queueResource.Metadata),
			})
		}

		account := storage.Account{
			Metadata:     resource.Metadata,
			NetworkRules: xslices.ZeroToNil(adaptNetworkRules(resource)),
			// The default value is true since API version 2019-04-01.
			EnforceHTTPS: resource.Properties.GetMapValue("supportsHttpsTrafficOnly").AsBoolValue(true, resource.Properties.GetMetadata()),
			Containers:   adaptContainers(resource, deployment),
			QueueProperties: storage.QueueProperties{
				Metadata:      resource.Properties.GetMetadata(),
				EnableLogging: types.BoolDefault(false, resource.Properties.GetMetadata()),
			},
			// The default interpretation is TLS 1.0 for this property.
			MinimumTLSVersion: resource.Properties.GetMapValue("minimumTlsVersion").
				AsStringValue("TLS1_0", resource.Properties.GetMetadata()),
			Queues: queues,
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
	return accounts
}

// adaptContainers collects the blob containers of a storage account, declared
// as its children, as children of its blob service, or as top-level resources
// named "<account name>/default/<container name>".
func adaptContainers(account azure.Resource, deployment azure.Deployment) []storage.Container {
	var containers []storage.Container
	for _, typ := range []string{"containerServices/containers", "blobServices/containers", containerType} {
		for _, resource := range account.GetResourcesByType(typ) {
			containers = append(containers, adaptContainer(resource))
		}
	}
	for _, service := range account.Resources {
		if !isBlobService(service.Type.AsString()) {
			continue
		}
		for _, typ := range []string{"containers", containerType} {
			for _, resource := range service.GetResourcesByType(typ) {
				containers = append(containers, adaptContainer(resource))
			}
		}
	}
	for _, resource := range deployment.GetResourcesByType(containerType) {
		if belongsToAccount(resource, account) {
			containers = append(containers, adaptContainer(resource))
		}
	}
	return containers
}

func isBlobService(typ string) bool {
	return typ == "blobServices" || typ == "Microsoft.Storage/storageAccounts/blobServices"
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

// belongsToAccount reports whether a top-level container belongs to account.
// When either name is an expression, which the parser does not evaluate, the
// container is kept.
func belongsToAccount(container, account azure.Resource) bool {
	containerName, accountName := container.Name.AsString(), account.Name.AsString()
	if containerName == "" || accountName == "" {
		return true
	}
	parent, _, found := strings.Cut(containerName, "/")
	return !found || strings.EqualFold(parent, accountName)
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

package storage

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
	xslices "github.com/aquasecurity/trivy/pkg/x/slices"
)

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

		var containers []storage.Container
		for _, containerResource := range resource.GetResourcesByType("containerServices/containers") {
			containers = append(containers, storage.Container{
				Metadata:     containerResource.Metadata,
				PublicAccess: containerResource.Properties.GetMapValue("publicAccess").AsStringValue("None", containerResource.Metadata),
			})
		}

		account := storage.Account{
			Metadata:     resource.Metadata,
			NetworkRules: xslices.ZeroToNil(adaptNetworkRules(resource)),
			// The default value is true since API version 2019-04-01.
			EnforceHTTPS: resource.Properties.GetMapValue("supportsHttpsTrafficOnly").AsBoolValue(true, resource.Properties.GetMetadata()),
			Containers:   containers,
			QueueProperties: storage.QueueProperties{
				Metadata:      resource.Properties.GetMetadata(),
				EnableLogging: types.BoolDefault(false, resource.Properties.GetMetadata()),
			},
			// The default interpretation is TLS 1.0 for this property.
			MinimumTLSVersion: resource.Properties.GetMapValue("minimumTlsVersion").
				AsStringValue("TLS1_0", resource.Properties.GetMetadata()),
			Queues:                          queues,
			BlobProperties:                  adaptBlobProperties(resource),
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

func adaptBlobProperties(account azure.Resource) storage.BlobProperties {
	service, ok := findBlobService(account)
	if !ok {
		return storage.BlobProperties{
			Metadata: account.Properties.GetMetadata(),
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Metadata: account.Properties.GetMetadata(),
				Days:     types.IntDefault(0, account.Properties.GetMetadata()),
			},
		}
	}

	policy := service.Properties.GetMapValue("deleteRetentionPolicy")
	if policy.IsNull() {
		return storage.BlobProperties{
			Metadata: service.Metadata,
			DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
				Metadata: service.Metadata,
				Days:     types.IntDefault(0, service.Metadata),
			},
		}
	}

	// With soft delete disabled, deleted blobs are removed immediately and days has no effect.
	// See https://learn.microsoft.com/en-us/rest/api/storageservices/set-blob-service-properties#request-body
	days := policy.GetMapValue("days").AsIntValue(0, policy.GetMetadata())
	if enabled := policy.GetMapValue("enabled").AsBoolValue(false, policy.GetMetadata()); enabled.IsFalse() {
		days = types.Int(0, enabled.GetMetadata())
	}

	return storage.BlobProperties{
		Metadata: service.Metadata,
		DeleteRetentionPolicy: storage.DeleteRetentionPolicy{
			Metadata: policy.GetMetadata(),
			Days:     days,
		},
	}
}

func findBlobService(account azure.Resource) (azure.Resource, bool) {
	for _, typ := range []string{"blobServices", "Microsoft.Storage/storageAccounts/blobServices"} {
		if services := account.GetResourcesByType(typ); len(services) > 0 {
			return services[0], true
		}
	}
	return azure.Resource{}, false
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

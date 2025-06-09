package storage

import (
	"strings"

	"github.com/samber/lo"

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
	return lo.Map(deployment.GetResourcesByType("Microsoft.Storage/storageAccounts"),
		func(r azure.Resource, _ int) storage.Account {
			return adaptStorageAccount(r)
		},
	)
}

func adaptStorageAccount(resource azure.Resource) storage.Account {
	propMetadata := resource.Properties.GetMetadata()
	return storage.Account{
		Metadata:     resource.Metadata,
		NetworkRules: xslices.ZeroToNil(adaptNetworkRules(resource)),
		// Default: true
		// https://github.com/Azure/bicep-registry-modules/blob/ce69fb2cef2a96e650b79932caaeab4454a5eb14/avm/res/storage/storage-account/main.bicep#L168
		EnforceHTTPS: resource.Properties.GetMapValue("supportsHttpsTrafficOnly").
			AsBoolValue(true, propMetadata),
		Containers: xslices.ZeroToNil(adaptContainers(resource)),
		QueueProperties: storage.QueueProperties{
			Metadata: types.NewUnmanagedMetadata(),
		},
		// Default: TLS1_2
		// See https://github.com/Azure/bicep-registry-modules/blob/ce69fb2cef2a96e650b79932caaeab4454a5eb14/avm/res/storage/storage-account/main.bicep#L122
		MinimumTLSVersion: resource.Properties.GetMapValue("minimumTlsVersion").
			AsStringValue("TLS1_2", propMetadata),
		Queues:              xslices.ZeroToNil(adaptQueues(resource)),
		PublicNetworkAccess: adaptPublicNetworkAccess(resource),
	}
}

func adaptPublicNetworkAccess(resource azure.Resource) types.BoolValue {
	// https://github.com/Azure/bicep-registry-modules/blob/ce69fb2cef2a96e650b79932caaeab4454a5eb14/avm/res/storage/storage-account/main.bicep#L446-L448
	publicAccess := resource.Properties.GetMapValue("publicNetworkAccess")
	if !publicAccess.IsNull() {
		return types.Bool(publicAccess.EqualTo("Enabled"), publicAccess.GetMetadata())
	}
	return types.BoolDefault(false, resource.Metadata)
}

func adaptContainers(resource azure.Resource) []storage.Container {
	// TODO: handle "Microsoft.Storage/storageAccounts/blobServices/containers"
	return lo.Map(resource.GetResourcesByType("blobServices/containers"),
		func(cr azure.Resource, _ int) storage.Container {
			return storage.Container{
				Metadata: cr.Metadata,
				// Default: None
				// https://github.com/Azure/bicep-registry-modules/blob/ce69fb2cef2a96e650b79932caaeab4454a5eb14/avm/res/storage/storage-account/blob-service/container/main.bicep#L44
				PublicAccess: cr.Properties.GetMapValue("publicAccess").AsStringValue("None", cr.Metadata),
			}
		})
}

func adaptQueues(resource azure.Resource) []storage.Queue {
	// TODO: handle "Microsoft.Storage/storageAccounts/queueServices/queues"
	return lo.Map(resource.GetResourcesByType("queueServices/queues"),
		func(qr azure.Resource, _ int) storage.Queue {
			return storage.Queue{
				Metadata: qr.Metadata,
				Name:     qr.Name.AsStringValue("", qr.Metadata),
			}
		})
}

func adaptNetworkRules(resource azure.Resource) []storage.NetworkRule {
	acl := resource.Properties.GetMapValue("networkAcls")
	if acl.IsNull() {
		return []storage.NetworkRule{{
			Metadata: resource.Metadata,
			// Default: AzureServices
			// See https://github.com/Azure/bicep-registry-modules/blob/ce69fb2cef2a96e650b79932caaeab4454a5eb14/avm/res/storage/storage-account/main.bicep#L441-L443
			Bypass:         []types.StringValue{types.StringDefault("AzureServices", resource.Metadata)},
			AllowByDefault: types.BoolDefault(false, resource.Metadata),
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
	}

	allowByDefault := types.Bool(false, acl.GetMetadata())
	if defaultAction := acl.GetMapValue("defaultAction"); !defaultAction.IsNull() {
		allowByDefault = types.Bool(defaultAction.EqualTo("Allow"), defaultAction.GetMetadata())
	}

	return []storage.NetworkRule{{
		Metadata:       acl.GetMetadata(),
		Bypass:         bypasses,
		AllowByDefault: allowByDefault,
	}}
}

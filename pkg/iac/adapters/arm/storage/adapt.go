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
			EnforceHTTPS: resource.Properties.GetMapValue("supportsHttpsTrafficOnly").AsBoolValue(false, resource.Properties.GetMetadata()),
			Containers:   containers,
			QueueProperties: storage.QueueProperties{
				Metadata:      resource.Properties.GetMetadata(),
				EnableLogging: types.BoolDefault(false, resource.Properties.GetMetadata()),
			},
			MinimumTLSVersion: resource.Properties.GetMapValue("minimumTlsVersion").AsStringValue("", resource.Properties.GetMetadata()),
			Queues:            queues,
		}

		publicNetworkAccess := resource.Properties.GetMapValue("publicNetworkAccess")
		account.PublicNetworkAccess = types.Bool(
			publicNetworkAccess.AsStringValue("Enabled", publicNetworkAccess.Metadata).EqualTo("Enabled"),
			publicNetworkAccess.Metadata,
		)
		accounts = append(accounts, account)
	}
	return accounts
}

func adaptNetworkRules(resource azure.Resource) []storage.NetworkRule {
	acl := resource.Properties.GetMapValue("networkAcls")
	if acl.IsNull() {
		return []storage.NetworkRule{{
			Metadata:       resource.Metadata,
			Bypass:         []types.StringValue{types.StringDefault("None", resource.Metadata)},
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

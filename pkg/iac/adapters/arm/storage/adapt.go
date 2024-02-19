package storage

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/storage"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) storage.Storage {
	return storage.Storage{
		Accounts: adaptAccounts(deployment),
	}
}

func adaptAccounts(deployment azure.Deployment) []storage.Account {
	var accounts []storage.Account
	for _, resource := range deployment.GetResourcesByType("Microsoft.Storage/storageAccounts") {

		var networkRules []storage.NetworkRule
		for _, acl := range resource.Properties.GetMapValue("networkAcls").AsList() {

			var bypasses []types.StringValue
			bypassProp := acl.GetMapValue("bypass")
			for _, bypass := range strings.Split(bypassProp.AsString(), ",") {
				bypasses = append(bypasses, types.String(bypass, bypassProp.GetMetadata()))
			}

			networkRules = append(networkRules, storage.NetworkRule{
				Metadata:       acl.GetMetadata(),
				Bypass:         bypasses,
				AllowByDefault: types.Bool(acl.GetMapValue("defaultAction").EqualTo("Allow"), acl.GetMetadata()),
			})
		}

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
			NetworkRules: networkRules,
			EnforceHTTPS: resource.Properties.GetMapValue("supportsHttpsTrafficOnly").AsBoolValue(false, resource.Properties.GetMetadata()),
			Containers:   containers,
			QueueProperties: storage.QueueProperties{
				Metadata:      resource.Properties.GetMetadata(),
				EnableLogging: types.BoolDefault(false, resource.Properties.GetMetadata()),
			},
			MinimumTLSVersion: resource.Properties.GetMapValue("minimumTlsVersion").AsStringValue("TLS1_0", resource.Properties.GetMetadata()),
			Queues:            queues,
		}
		accounts = append(accounts, account)
	}
	return accounts
}

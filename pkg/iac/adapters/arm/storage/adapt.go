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
		account.DiagnosticLogging = adaptDiagnosticLogging(deployment, resource)
		accounts = append(accounts, account)
	}
	return accounts
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

const diagnosticSettingType = "Microsoft.Insights/diagnosticSettings"

// diagnosticSetting pairs a diagnostic setting resource with the storage
// service it logs requests for.
type diagnosticSetting struct {
	resource azure.Resource
	service  string
}

// adaptDiagnosticLogging returns, per storage service, whether request logging
// is enabled through an Azure Monitor diagnostic setting targeting the
// account or one of its services.
func adaptDiagnosticLogging(deployment azure.Deployment, account azure.Resource) storage.DiagnosticLogging {
	logging := storage.DiagnosticLogging{
		Metadata: account.Metadata,
		Blob:     types.BoolDefault(false, account.Metadata),
		File:     types.BoolDefault(false, account.Metadata),
		Queue:    types.BoolDefault(false, account.Metadata),
		Table:    types.BoolDefault(false, account.Metadata),
	}
	for _, setting := range diagnosticSettingsForAccount(deployment, account) {
		if !diagnosticSettingLogsRequests(setting.resource) {
			continue
		}
		if field := diagnosticSettingField(setting.service, &logging); field != nil {
			*field = types.Bool(true, setting.resource.Metadata)
		}
	}
	return logging
}

// diagnosticSettingField returns the DiagnosticLogging field for a storage
// service, or nil when the service is not one of the storage services.
func diagnosticSettingField(service string, logging *storage.DiagnosticLogging) *types.BoolValue {
	switch service {
	case "blob":
		return &logging.Blob
	case "file":
		return &logging.File
	case "queue":
		return &logging.Queue
	case "table":
		return &logging.Table
	default:
		return nil
	}
}

// diagnosticSettingsForAccount returns the diagnostic settings targeting the
// given storage account, each with the storage service it logs for. Settings
// are found by their scope, when declared at the top level, or by nesting
// under one of the account's service resources. A setting targeting the
// account itself is ignored: it can only carry metrics, not request logs.
func diagnosticSettingsForAccount(deployment azure.Deployment, account azure.Resource) []diagnosticSetting {
	var settings []diagnosticSetting
	for _, setting := range deployment.GetResourcesByType(diagnosticSettingType) {
		if service := diagnosticSettingService(setting, account); service != "" {
			settings = append(settings, diagnosticSetting{resource: setting, service: service})
		}
	}
	for _, service := range []struct {
		resourceType string
		name         string
	}{
		{"blobServices", "blob"},
		{"fileServices", "file"},
		{"queueServices", "queue"},
		{"tableServices", "table"},
	} {
		for _, serviceResource := range serviceResourcesForAccount(deployment, account, service.resourceType) {
			for _, setting := range serviceResource.GetResourcesByType(diagnosticSettingType) {
				settings = append(settings, diagnosticSetting{resource: setting, service: service.name})
			}
		}
	}
	return settings
}

// serviceResourcesForAccount returns the storage service resources belonging
// to the given account, whether nested under it or declared at the top level
// with the account name as a prefix.
func serviceResourcesForAccount(deployment azure.Deployment, account azure.Resource, serviceType string) []azure.Resource {
	fullType := "Microsoft.Storage/storageAccounts/" + serviceType
	matches := func(t string) bool { return t == serviceType || t == fullType }
	var resources []azure.Resource
	for _, child := range account.Resources {
		if matches(child.Type.AsString()) {
			resources = append(resources, child)
		}
	}
	if name := valueString(account.Name); name != "" {
		for _, resource := range deployment.GetResourcesByType(fullType) {
			if strings.HasPrefix(valueString(resource.Name), name+"/") {
				resources = append(resources, resource)
			}
		}
	}
	return resources
}

// diagnosticSettingService returns which storage service a top-level
// diagnostic setting targets, based on its scope, or "" when the setting
// does not target this account or targets the account itself.
func diagnosticSettingService(setting azure.Resource, account azure.Resource) string {
	scope := strings.ToLower(valueString(setting.Scope))
	if scope == "" || !scopeTargetsAccount(scope, account) {
		return ""
	}
	switch {
	case scopeHasService(scope, "blobservices"):
		return "blob"
	case scopeHasService(scope, "fileservices"):
		return "file"
	case scopeHasService(scope, "queueservices"):
		return "queue"
	case scopeHasService(scope, "tableservices"):
		return "table"
	default:
		return ""
	}
}

// scopeHasService reports whether a scope names the given storage service,
// either as a path segment of a literal resource ID or as an argument of an
// ARM expression such as resourceId('.../blobServices', ...).
func scopeHasService(scope, service string) bool {
	i := strings.Index(scope, "/"+service)
	if i < 0 {
		return false
	}
	rest := scope[i+len(service)+1:]
	return rest == "" || strings.HasPrefix(rest, "/") || strings.HasPrefix(rest, "'") ||
		strings.HasPrefix(rest, `"`) || strings.HasPrefix(rest, ",") || strings.HasPrefix(rest, ")")
}

// valueString returns the string content of a value, whether it is a literal
// string or an ARM expression.
func valueString(v azure.Value) string {
	if s, ok := v.Raw().(string); ok {
		return s
	}
	return ""
}

// scopeTargetsAccount reports whether a diagnostic setting scope names the
// given storage account, either as a literal resource ID or as an ARM
// expression such as resourceId('...', 'name', ...) naming the account.
func scopeTargetsAccount(scope string, account azure.Resource) bool {
	name := strings.ToLower(valueString(account.Name))
	if name == "" {
		return false
	}
	if i := strings.Index(scope, "/storageaccounts/"); i >= 0 {
		rest := scope[i+len("/storageaccounts/"):]
		if j := strings.Index(rest, "/"); j >= 0 {
			rest = rest[:j]
		}
		// A literal resource ID names the account in this segment; an
		// expression scope has the service or a placeholder here instead,
		// so fall through to the expression checks below.
		if !strings.ContainsAny(rest, "'\"({") {
			return rest == name
		}
	}
	// The scope is an ARM expression: the account name appears as a quoted
	// argument, or the account name is itself an expression used in it.
	if strings.Contains(scope, "'"+name+"'") || strings.Contains(scope, `"`+name+`"`) {
		return true
	}
	if strings.Contains(name, "(") {
		return strings.Contains(scope, name)
	}
	return false
}

// diagnosticSettingLogsRequests reports whether a diagnostic setting enables
// request logging for a storage service. Disabled log entries, metric entries
// and other log categories do not count.
func diagnosticSettingLogsRequests(setting azure.Resource) bool {
	for _, logEntry := range setting.Properties.GetMapValue("logs").AsList() {
		if !logEntry.GetMapValue("enabled").AsBoolValue(true, logEntry.GetMetadata()).IsTrue() {
			continue
		}
		if category := logEntry.GetMapValue("category"); !category.IsNull() {
			for _, want := range storage.DiagnosticLogCategories {
				if category.EqualTo(want) {
					return true
				}
			}
		}
		if group := logEntry.GetMapValue("categoryGroup"); !group.IsNull() && group.EqualTo("allLogs") {
			return true
		}
	}
	return false
}

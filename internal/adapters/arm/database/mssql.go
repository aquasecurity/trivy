package database

import (
	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/aquasecurity/trivy/pkg/scanners/azure"
)

func adaptMSSQLServers(deployment azure.Deployment) (msSQlServers []database.MSSQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Sql/servers") {
		msSQlServers = append(msSQlServers, adaptMSSQLServer(resource, deployment))
	}
	return msSQlServers
}

func adaptMSSQLServer(resource azure.Resource, deployment azure.Deployment) database.MSSQLServer {
	return database.MSSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      resource.Properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         resource.Properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: resource.Properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource),
		},
		ExtendedAuditingPolicies: adaptExtendedAuditingPolicies(resource, deployment),
		SecurityAlertPolicies:    adaptSecurityAlertPolicies(resource, deployment),
	}
}

func adaptExtendedAuditingPolicies(resource azure.Resource, deployment azure.Deployment) (policies []database.ExtendedAuditingPolicy) {

	for _, policy := range deployment.GetResourcesByType("Microsoft.Sql/servers/extendedAuditingSettings") {
		policies = append(policies, database.ExtendedAuditingPolicy{
			Metadata:        policy.Metadata,
			RetentionInDays: policy.Properties.GetMapValue("retentionDays").AsIntValue(0, policy.Metadata),
		})
	}

	return policies
}

func adaptSecurityAlertPolicies(resource azure.Resource, deployment azure.Deployment) (policies []database.SecurityAlertPolicy) {
	for _, policy := range deployment.GetResourcesByType("Microsoft.Sql/servers/securityAlertPolicies") {
		policies = append(policies, database.SecurityAlertPolicy{
			Metadata:           policy.Metadata,
			EmailAddresses:     adaptStringList(policy.Properties.GetMapValue("emailAddresses")),
			DisabledAlerts:     adaptStringList(policy.Properties.GetMapValue("disabledAlerts")),
			EmailAccountAdmins: policy.Properties.GetMapValue("emailAccountAdmins").AsBoolValue(false, policy.Metadata),
		})
	}
	return policies
}

func adaptStringList(value azure.Value) []defsecTypes.StringValue {
	var list []defsecTypes.StringValue
	for _, v := range value.AsList() {
		list = append(list, v.AsStringValue("", value.Metadata))
	}
	return list
}

package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	azure2 "github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptMSSQLServers(deployment azure2.Deployment) (msSQlServers []database.MSSQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Sql/servers") {
		msSQlServers = append(msSQlServers, adaptMSSQLServer(resource, deployment))
	}
	return msSQlServers
}

func adaptMSSQLServer(resource azure2.Resource, deployment azure2.Deployment) database.MSSQLServer {
	properties := resource.Properties
	administratorLogin := properties.GetMapValue("administratorLogin").AsStringValue("")

	// Support for azureadAdministrator block (ARM uses administrators property)
	var adAdmins []database.ActiveDirectoryAdministrator
	administrators := properties.GetMapValue("administrators")
	if administrators.Kind != azure2.KindNull {
		login := administrators.GetMapValue("login").AsStringValue("")
		if !login.IsEmpty() {
			adAdmins = append(adAdmins, database.ActiveDirectoryAdministrator{
				Metadata: administrators.GetMetadata(),
				Login:    login,
			})
		}
	}

	return database.MSSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata: resource.Metadata,
			// TODO: this property doesn't exist.
			EnableSSLEnforcement:      properties.GetMapValue("sslEnforcement").AsBoolValue(false),
			MinimumTLSVersion:         properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled"),
			EnablePublicNetworkAccess: properties.GetMapValue("publicNetworkAccess").AsBoolValue(false),
			FirewallRules:             addFirewallRule(resource),
		},
		ExtendedAuditingPolicies:      adaptExtendedAuditingPolicies(resource, deployment),
		SecurityAlertPolicies:         adaptSecurityAlertPolicies(resource, deployment),
		AdministratorLogin:            administratorLogin,
		ActiveDirectoryAdministrators: adAdmins,
	}
}

func adaptExtendedAuditingPolicies(_ azure2.Resource, deployment azure2.Deployment) (policies []database.ExtendedAuditingPolicy) {

	for _, policy := range deployment.GetResourcesByType("Microsoft.Sql/servers/extendedAuditingSettings") {
		policies = append(policies, database.ExtendedAuditingPolicy{
			Metadata:        policy.Metadata,
			RetentionInDays: policy.Properties.GetMapValue("retentionDays").AsIntValue(0),
		})
	}

	return policies
}

func adaptSecurityAlertPolicies(_ azure2.Resource, deployment azure2.Deployment) (policies []database.SecurityAlertPolicy) {
	for _, policy := range deployment.GetResourcesByType("Microsoft.Sql/servers/securityAlertPolicies") {
		policies = append(policies, database.SecurityAlertPolicy{
			Metadata:           policy.Metadata,
			EmailAddresses:     adaptStringList(policy.Properties.GetMapValue("emailAddresses")),
			DisabledAlerts:     adaptStringList(policy.Properties.GetMapValue("disabledAlerts")),
			EmailAccountAdmins: policy.Properties.GetMapValue("emailAccountAdmins").AsBoolValue(false),
		})
	}
	return policies
}

func adaptStringList(value azure2.Value) []iacTypes.StringValue {
	var list []iacTypes.StringValue
	for _, v := range value.AsList() {
		list = append(list, v.AsStringValue(""))
	}
	return list
}

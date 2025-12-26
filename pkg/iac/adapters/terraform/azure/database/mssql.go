package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptMSSQLServers(modules terraform.Modules) []database.MSSQLServer {
	var mssqlServers []database.MSSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_sql_server", "azurerm_mssql_server") {
			mssqlServers = append(mssqlServers, adaptMSSQLServer(resource, module))
		}
	}
	return mssqlServers
}

func adaptMSSQLServer(resource *terraform.Block, module *terraform.Module) database.MSSQLServer {
	minTLSVersionVal := iacTypes.StringDefault("", resource.GetMetadata())
	publicAccessVal := iacTypes.BoolDefault(true, resource.GetMetadata())
	enableSSLEnforcementVal := iacTypes.BoolDefault(false, resource.GetMetadata())

	if resource.TypeLabel() == "azurerm_mssql_server" {
		minTLSVersionAttr := resource.GetAttribute("minimum_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("1.2", resource)
		publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
		publicAccessVal = publicAccessAttr.AsBoolValueOrDefault(true, resource)
	}

	var alertPolicies []database.SecurityAlertPolicy
	alertPolicyBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_security_alert_policy", "server_name")
	for _, alertBlock := range alertPolicyBlocks {
		alertPolicies = append(alertPolicies, adaptMSSQLSecurityAlertPolicy(alertBlock))
	}

	auditingPoliciesBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_extended_auditing_policy", "server_id")
	auditingPoliciesBlocks = append(auditingPoliciesBlocks, resource.GetBlocks("extended_auditing_policy")...)

	databasesRes := module.GetReferencingResources(resource, "azurerm_mssql_database", "server_id")
	for _, databaseRes := range databasesRes {
		dbAuditingBlocks := module.GetReferencingResources(databaseRes, "azurerm_mssql_database_extended_auditing_policy", "database_id")
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, dbAuditingBlocks...)
	}

	var auditingPolicies []database.ExtendedAuditingPolicy
	for _, auditBlock := range auditingPoliciesBlocks {
		auditingPolicies = append(auditingPolicies, adaptMSSQLExtendedAuditingPolicy(auditBlock))
	}

	var firewallRules []database.FirewallRule
	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_sql_firewall_rule", "server_name")
	firewallRuleBlocks = append(firewallRuleBlocks, module.GetReferencingResources(resource, "azurerm_mssql_firewall_rule", "server_id")...)
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	// Support for deprecated azuread_administrator block (backward compatibility)
	var adAdmins []database.ActiveDirectoryAdministrator
	azureadAdminBlock := resource.GetBlock("azuread_administrator")
	if azureadAdminBlock.IsNotNil() {
		adAdmins = append(adAdmins, adaptAzureADAdministratorBlock(azureadAdminBlock))
	}

	// Support for azurerm_sql_active_directory_administrator resource (preferred method)
	adAdminBlocks := module.GetReferencingResources(resource, "azurerm_sql_active_directory_administrator", "server_name")
	for _, adAdminBlock := range adAdminBlocks {
		adAdmins = append(adAdmins, adaptActiveDirectoryAdministrator(adAdminBlock))
	}

	return database.MSSQLServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
		ExtendedAuditingPolicies:      auditingPolicies,
		SecurityAlertPolicies:         alertPolicies,
		AdministratorLogin:            resource.GetAttribute("administrator_login").AsStringValueOrDefault("", resource),
		ActiveDirectoryAdministrators: adAdmins,
	}
}

func adaptMSSQLSecurityAlertPolicy(resource *terraform.Block) database.SecurityAlertPolicy {
	return database.SecurityAlertPolicy{
		Metadata:       resource.GetMetadata(),
		EmailAddresses: resource.GetAttribute("email_addresses").AsStringValues(),
		DisabledAlerts: resource.GetAttribute("disabled_alerts").AsStringValues(),
		EmailAccountAdmins: resource.GetAttribute("email_account_admins").
			AsBoolValueOrDefault(false, resource),
	}
}

func adaptMSSQLExtendedAuditingPolicy(resource *terraform.Block) database.ExtendedAuditingPolicy {
	return database.ExtendedAuditingPolicy{
		Metadata:        resource.GetMetadata(),
		RetentionInDays: resource.GetAttribute("retention_in_days").AsIntValueOrDefault(0, resource),
	}
}

func adaptActiveDirectoryAdministrator(resource *terraform.Block) database.ActiveDirectoryAdministrator {
	return database.ActiveDirectoryAdministrator{
		Metadata: resource.GetMetadata(),
		Login:    resource.GetAttribute("login").AsStringValueOrDefault("", resource),
	}
}

func adaptAzureADAdministratorBlock(block *terraform.Block) database.ActiveDirectoryAdministrator {
	return database.ActiveDirectoryAdministrator{
		Metadata: block.GetMetadata(),
		// The azuread_administrator block uses login_username attribute
		Login: block.GetFirstAttributeOf("login_username", "login").
			AsStringValueOrDefault("", block),
	}
}

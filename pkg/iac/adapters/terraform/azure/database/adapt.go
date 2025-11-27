package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) database.Database {
	return database.Database{
		MSSQLServers:      adaptMSSQLServers(modules),
		MariaDBServers:    adaptMariaDBServers(modules),
		MySQLServers:      adaptMySQLServers(modules),
		PostgreSQLServers: adaptPostgreSQLServers(modules),
	}
}

func adaptMSSQLServers(modules terraform.Modules) []database.MSSQLServer {
	var mssqlServers []database.MSSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_sql_server") {
			mssqlServers = append(mssqlServers, adaptMSSQLServer(resource, module))
		}
		for _, resource := range module.GetResourcesByType("azurerm_mssql_server") {
			mssqlServers = append(mssqlServers, adaptMSSQLServer(resource, module))
		}
	}
	return mssqlServers
}

func adaptMySQLServers(modules terraform.Modules) []database.MySQLServer {
	var mySQLServers []database.MySQLServer
	for _, module := range modules {
		// Support legacy azurerm_mysql_server
		for _, resource := range module.GetResourcesByType("azurerm_mysql_server") {
			mySQLServers = append(mySQLServers, adaptMySQLServer(resource, module))
		}
		// Support new azurerm_mysql_flexible_server
		for _, resource := range module.GetResourcesByType("azurerm_mysql_flexible_server") {
			mySQLServers = append(mySQLServers, adaptMySQLFlexibleServer(resource, module))
		}
	}
	return mySQLServers
}

func adaptMariaDBServers(modules terraform.Modules) []database.MariaDBServer {
	var mariaDBServers []database.MariaDBServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mariadb_server") {
			mariaDBServers = append(mariaDBServers, adaptMariaDBServer(resource, module))
		}
	}

	return mariaDBServers
}

func adaptPostgreSQLServers(modules terraform.Modules) []database.PostgreSQLServer {
	var postgreSQLServers []database.PostgreSQLServer
	for _, module := range modules {
		// Support legacy azurerm_postgresql_server
		for _, resource := range module.GetResourcesByType("azurerm_postgresql_server") {
			postgreSQLServers = append(postgreSQLServers, adaptPostgreSQLServer(resource, module))
		}
		// Support new azurerm_postgresql_flexible_server
		for _, resource := range module.GetResourcesByType("azurerm_postgresql_flexible_server") {
			postgreSQLServers = append(postgreSQLServers, adaptPostgreSQLFlexibleServer(resource, module))
		}
	}

	return postgreSQLServers
}

func adaptMSSQLServer(resource *terraform.Block, module *terraform.Module) database.MSSQLServer {
	minTLSVersionVal := iacTypes.StringDefault("", resource.GetMetadata())
	publicAccessVal := iacTypes.BoolDefault(true, resource.GetMetadata())
	enableSSLEnforcementVal := iacTypes.BoolDefault(false, resource.GetMetadata())

	var auditingPolicies []database.ExtendedAuditingPolicy
	var alertPolicies []database.SecurityAlertPolicy
	var firewallRules []database.FirewallRule

	if resource.TypeLabel() == "azurerm_mssql_server" {
		minTLSVersionAttr := resource.GetAttribute("minimum_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("1.2", resource)
		publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
		publicAccessVal = publicAccessAttr.AsBoolValueOrDefault(true, resource)
	}

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

	for _, auditBlock := range auditingPoliciesBlocks {
		auditingPolicies = append(auditingPolicies, adaptMSSQLExtendedAuditingPolicy(auditBlock))
	}

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

func adaptMySQLServer(resource *terraform.Block, module *terraform.Module) database.MySQLServer {
	var firewallRules []database.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLS1_2", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mysql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MySQLServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func adaptMySQLFlexibleServer(resource *terraform.Block, module *terraform.Module) database.MySQLServer {
	var firewallRules []database.FirewallRule

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	// Flexible server firewall rules use server_id instead of server_name
	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mysql_flexible_server_firewall_rule", "server_id")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	// MySQL Flexible Server configurations (new standalone resource)
	// TLS settings are configured through azurerm_mysql_flexible_server_configuration resources
	// Each configuration resource manages a single parameter specified in the name attribute
	// By default, the server enforces secure connections using TLS 1.2
	configBlocks := module.GetReferencingResources(resource, "azurerm_mysql_flexible_server_configuration", "server_id")
	params := parseServerParameters(configBlocks, resource.GetMetadata())

	return database.MySQLServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      params.requireSecureTransport,
			MinimumTLSVersion:         params.tlsVersion,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func adaptMariaDBServer(resource *terraform.Block, module *terraform.Module) database.MariaDBServer {
	var firewallRules []database.FirewallRule

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mariadb_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MariaDBServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata: resource.GetMetadata(),
			EnableSSLEnforcement: resource.GetAttribute("ssl_enforcement_enabled").
				AsBoolValueOrDefault(false, resource),
			MinimumTLSVersion: iacTypes.StringDefault("", resource.GetMetadata()),
			EnablePublicNetworkAccess: resource.GetAttribute("public_network_access_enabled").
				AsBoolValueOrDefault(true, resource),
			FirewallRules: firewallRules,
		},
	}
}

func adaptPostgreSQLServer(resource *terraform.Block, module *terraform.Module) database.PostgreSQLServer {
	var firewallRules []database.FirewallRule

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	configBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_configuration", "server_name")
	config := adaptPostgreSQLConfig(resource, configBlocks)

	threatDetectionBlock := resource.GetBlock("threat_detection_policy")
	threatDetectionPolicy := adaptThreatDetectionPolicy(threatDetectionBlock, resource.GetMetadata())

	return database.PostgreSQLServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata: resource.GetMetadata(),
			EnableSSLEnforcement: resource.GetAttribute("ssl_enforcement_enabled").
				AsBoolValueOrDefault(false, resource),
			MinimumTLSVersion: resource.GetAttribute("ssl_minimal_tls_version_enforced").
				AsStringValueOrDefault("TLS1_2", resource),
			EnablePublicNetworkAccess: resource.GetAttribute("public_network_access_enabled").
				AsBoolValueOrDefault(true, resource),
			FirewallRules: firewallRules,
		},
		Config: config,
		GeoRedundantBackupEnabled: resource.GetAttribute("geo_redundant_backup_enabled").
			AsBoolValueOrDefault(false, resource),
		ThreatDetectionPolicy: threatDetectionPolicy,
	}
}

func adaptPostgreSQLFlexibleServer(resource *terraform.Block, module *terraform.Module) database.PostgreSQLServer {
	var firewallRules []database.FirewallRule

	// Flexible server firewall rules use server_id instead of server_name
	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_flexible_server_firewall_rule", "server_id")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	// PostgreSQL Flexible Server configurations (new standalone resource)
	// TLS settings are configured through azurerm_postgresql_flexible_server_configuration resources
	// Each configuration resource manages a single parameter specified in the name attribute
	// By default, the server enforces secure connections using TLS 1.2
	// Flexible server configurations use server_id instead of server_name
	configBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_flexible_server_configuration", "server_id")
	config := adaptPostgreSQLConfig(resource, configBlocks)

	// Threat Detection is not configurable via Terraform for PostgreSQL Flexible Server
	// It can only be configured via Azure CLI, so we mark it as unmanaged to avoid false positives
	threatDetectionBlock := resource.GetBlock("threat_detection_policy")
	threatDetectionPolicy := adaptThreatDetectionPolicy(threatDetectionBlock, iacTypes.NewUnmanagedMetadata())

	params := parseServerParameters(configBlocks, resource.GetMetadata())

	return database.PostgreSQLServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata:             resource.GetMetadata(),
			EnableSSLEnforcement: params.requireSecureTransport,
			MinimumTLSVersion:    params.tlsVersion,
			EnablePublicNetworkAccess: resource.GetAttribute("public_network_access_enabled").
				AsBoolValueOrDefault(true, resource),
			FirewallRules: firewallRules,
		},
		Config: config,
		GeoRedundantBackupEnabled: resource.GetAttribute("geo_redundant_backup_enabled").
			AsBoolValueOrDefault(false, resource),
		ThreatDetectionPolicy: threatDetectionPolicy,
	}
}

func adaptPostgreSQLConfig(resource *terraform.Block, configBlocks []*terraform.Block) database.PostgresSQLConfig {
	var defaultMetadata iacTypes.Metadata
	if resource != nil {
		defaultMetadata = resource.GetMetadata()
	} else {
		defaultMetadata = iacTypes.NewUnmanagedMetadata()
	}

	config := database.PostgresSQLConfig{
		Metadata:             defaultMetadata,
		LogCheckpoints:       iacTypes.BoolDefault(false, defaultMetadata),
		ConnectionThrottling: iacTypes.BoolDefault(false, defaultMetadata),
		LogConnections:       iacTypes.BoolDefault(false, defaultMetadata),
		LogDisconnections:    iacTypes.BoolDefault(false, defaultMetadata),
	}

	for _, configBlock := range configBlocks {

		nameAttr := configBlock.GetAttribute("name")
		valAttr := configBlock.GetAttribute("value")

		if nameAttr.Equals("log_checkpoints") {
			config.LogCheckpoints = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
		if nameAttr.Equals("connection_throttling") {
			config.ConnectionThrottling = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
		if nameAttr.Equals("log_connections") {
			config.LogConnections = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
		if nameAttr.Equals("log_disconnections") {
			config.LogDisconnections = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
	}

	return config
}

func adaptMSSQLSecurityAlertPolicy(resource *terraform.Block) database.SecurityAlertPolicy {

	emailAddressesAttr := resource.GetAttribute("email_addresses")
	disabledAlertsAttr := resource.GetAttribute("disabled_alerts")

	emailAccountAdminsAttr := resource.GetAttribute("email_account_admins")
	emailAccountAdminsVal := emailAccountAdminsAttr.AsBoolValueOrDefault(false, resource)

	return database.SecurityAlertPolicy{
		Metadata:           resource.GetMetadata(),
		EmailAddresses:     emailAddressesAttr.AsStringValues(),
		DisabledAlerts:     disabledAlertsAttr.AsStringValues(),
		EmailAccountAdmins: emailAccountAdminsVal,
	}
}

func adaptFirewallRule(resource *terraform.Block) database.FirewallRule {
	startIPAttr := resource.GetAttribute("start_ip_address")
	startIPVal := startIPAttr.AsStringValueOrDefault("", resource)

	endIPAttr := resource.GetAttribute("end_ip_address")
	endIPVal := endIPAttr.AsStringValueOrDefault("", resource)

	return database.FirewallRule{
		Metadata: resource.GetMetadata(),
		StartIP:  startIPVal,
		EndIP:    endIPVal,
	}
}

func adaptMSSQLExtendedAuditingPolicy(resource *terraform.Block) database.ExtendedAuditingPolicy {
	retentionInDaysAttr := resource.GetAttribute("retention_in_days")
	retentionInDaysVal := retentionInDaysAttr.AsIntValueOrDefault(0, resource)

	return database.ExtendedAuditingPolicy{
		Metadata:        resource.GetMetadata(),
		RetentionInDays: retentionInDaysVal,
	}
}

func adaptActiveDirectoryAdministrator(resource *terraform.Block) database.ActiveDirectoryAdministrator {
	loginAttr := resource.GetAttribute("login")
	loginVal := loginAttr.AsStringValueOrDefault("", resource)

	return database.ActiveDirectoryAdministrator{
		Metadata: resource.GetMetadata(),
		Login:    loginVal,
	}
}

func adaptAzureADAdministratorBlock(block *terraform.Block) database.ActiveDirectoryAdministrator {
	// The azuread_administrator block uses login_username attribute
	loginVal := block.GetFirstAttributeOf("login_username", "login").AsStringValueOrDefault("", block)

	return database.ActiveDirectoryAdministrator{
		Metadata: block.GetMetadata(),
		Login:    loginVal,
	}
}

func adaptThreatDetectionPolicy(block *terraform.Block, defaultMetadata iacTypes.Metadata) database.ThreatDetectionPolicy {
	if block.IsNil() {
		return database.ThreatDetectionPolicy{
			Metadata: defaultMetadata,
			Enabled:  iacTypes.BoolDefault(false, defaultMetadata),
		}
	}

	return database.ThreatDetectionPolicy{
		Metadata: block.GetMetadata(),
		Enabled:  block.GetAttribute("enabled").AsBoolValueOrDefault(false, block),
	}
}

// serverParameters represents server configuration parameters that are common
// to both MySQL and PostgreSQL flexible servers in Azure.
type serverParameters struct {
	requireSecureTransport iacTypes.BoolValue
	tlsVersion             iacTypes.StringValue
}

// parseServerParameters parses a list of server configurations to extract
// server parameters for MySQL and PostgreSQL flexible servers.
func parseServerParameters(configs []*terraform.Block, resourceMetadata iacTypes.Metadata) serverParameters {
	// https://learn.microsoft.com/en-us/azure/mysql/flexible-server/overview#enterprise-grade-security-compliance-and-privacy
	params := serverParameters{
		requireSecureTransport: iacTypes.BoolDefault(true, resourceMetadata),
		tlsVersion:             iacTypes.StringDefault("TLS1.2", resourceMetadata),
	}

	for _, config := range configs {
		nameAttr := config.GetAttribute("name")
		valAttr := config.GetAttribute("value")
		switch {
		case nameAttr.Equals("require_secure_transport"):
			params.requireSecureTransport, _ = iacTypes.BoolFromCtyValue(valAttr.Value(), valAttr.GetMetadata())
		case nameAttr.Equals("tls_version"):
			params.tlsVersion = valAttr.AsStringValueOrDefault("TLS1_2", config)
		}
	}

	return params
}

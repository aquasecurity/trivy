package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(modules terraform.Modules) database.Database {

	mssqlAdapter := mssqlAdapter{
		alertPolicyIDs:    modules.GetChildResourceIDMapByType("azurerm_mssql_server_security_alert_policy"),
		auditingPolicyIDs: modules.GetChildResourceIDMapByType("azurerm_mssql_server_extended_auditing_policy", "azurerm_mssql_database_extended_auditing_policy"),
		firewallIDs:       modules.GetChildResourceIDMapByType("azurerm_sql_firewall_rule", "azurerm_mssql_firewall_rule"),
	}

	mysqlAdapter := mysqlAdapter{
		firewallIDs: modules.GetChildResourceIDMapByType("azurerm_mysql_firewall_rule"),
	}

	mariaDBAdapter := mariaDBAdapter{
		firewallIDs: modules.GetChildResourceIDMapByType("azurerm_mariadb_firewall_rule"),
	}

	postgresqlAdapter := postgresqlAdapter{
		firewallIDs: modules.GetChildResourceIDMapByType("azurerm_postgresql_firewall_rule"),
	}

	return database.Database{
		MSSQLServers:      mssqlAdapter.adaptMSSQLServers(modules),
		MariaDBServers:    mariaDBAdapter.adaptMariaDBServers(modules),
		MySQLServers:      mysqlAdapter.adaptMySQLServers(modules),
		PostgreSQLServers: postgresqlAdapter.adaptPostgreSQLServers(modules),
	}
}

type mssqlAdapter struct {
	alertPolicyIDs    terraform.ResourceIDResolutions
	auditingPolicyIDs terraform.ResourceIDResolutions
	firewallIDs       terraform.ResourceIDResolutions
}

type mysqlAdapter struct {
	firewallIDs terraform.ResourceIDResolutions
}

type mariaDBAdapter struct {
	firewallIDs terraform.ResourceIDResolutions
}

type postgresqlAdapter struct {
	firewallIDs terraform.ResourceIDResolutions
}

func (a *mssqlAdapter) adaptMSSQLServers(modules terraform.Modules) []database.MSSQLServer {
	var mssqlServers []database.MSSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_sql_server") {
			mssqlServers = append(mssqlServers, a.adaptMSSQLServer(resource, module))
		}
		for _, resource := range module.GetResourcesByType("azurerm_mssql_server") {
			mssqlServers = append(mssqlServers, a.adaptMSSQLServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.alertPolicyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database.MSSQLServer{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Server: database.Server{
				Metadata:                  iacTypes.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				MinimumTLSVersion:         iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
			ExtendedAuditingPolicies: nil,
			SecurityAlertPolicies:    nil,
		}
		for _, policy := range orphanResources {
			orphanage.SecurityAlertPolicies = append(orphanage.SecurityAlertPolicies, adaptMSSQLSecurityAlertPolicy(policy))
		}
		mssqlServers = append(mssqlServers, orphanage)

	}

	orphanResources = modules.GetResourceByIDs(a.auditingPolicyIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database.MSSQLServer{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Server: database.Server{
				Metadata:                  iacTypes.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				MinimumTLSVersion:         iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
		}
		for _, policy := range orphanResources {
			orphanage.ExtendedAuditingPolicies = append(orphanage.ExtendedAuditingPolicies, adaptMSSQLExtendedAuditingPolicy(policy))
		}
		mssqlServers = append(mssqlServers, orphanage)

	}

	orphanResources = modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database.MSSQLServer{
			Metadata: iacTypes.NewUnmanagedMetadata(),
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		mssqlServers = append(mssqlServers, orphanage)

	}

	return mssqlServers
}
func (a *mysqlAdapter) adaptMySQLServers(modules terraform.Modules) []database.MySQLServer {
	var mySQLServers []database.MySQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mysql_server") {
			mySQLServers = append(mySQLServers, a.adaptMySQLServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database.MySQLServer{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Server: database.Server{
				Metadata:                  iacTypes.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				MinimumTLSVersion:         iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		mySQLServers = append(mySQLServers, orphanage)

	}

	return mySQLServers
}

func (a *mariaDBAdapter) adaptMariaDBServers(modules terraform.Modules) []database.MariaDBServer {
	var mariaDBServers []database.MariaDBServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mariadb_server") {
			mariaDBServers = append(mariaDBServers, a.adaptMariaDBServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database.MariaDBServer{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Server: database.Server{
				Metadata:                  iacTypes.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				MinimumTLSVersion:         iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		mariaDBServers = append(mariaDBServers, orphanage)

	}

	return mariaDBServers
}

func (a *postgresqlAdapter) adaptPostgreSQLServers(modules terraform.Modules) []database.PostgreSQLServer {
	var postgreSQLServers []database.PostgreSQLServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_postgresql_server") {
			postgreSQLServers = append(postgreSQLServers, a.adaptPostgreSQLServer(resource, module))
		}
	}

	orphanResources := modules.GetResourceByIDs(a.firewallIDs.Orphans()...)

	if len(orphanResources) > 0 {
		orphanage := database.PostgreSQLServer{
			Metadata: iacTypes.NewUnmanagedMetadata(),
			Server: database.Server{
				Metadata:                  iacTypes.NewUnmanagedMetadata(),
				EnableSSLEnforcement:      iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				MinimumTLSVersion:         iacTypes.StringDefault("", iacTypes.NewUnmanagedMetadata()),
				EnablePublicNetworkAccess: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				FirewallRules:             nil,
			},
			Config: database.PostgresSQLConfig{
				Metadata:             iacTypes.NewUnmanagedMetadata(),
				LogCheckpoints:       iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				ConnectionThrottling: iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
				LogConnections:       iacTypes.BoolDefault(false, iacTypes.NewUnmanagedMetadata()),
			},
		}
		for _, policy := range orphanResources {
			orphanage.FirewallRules = append(orphanage.FirewallRules, adaptFirewallRule(policy))
		}
		postgreSQLServers = append(postgreSQLServers, orphanage)

	}

	return postgreSQLServers
}

func (a *mssqlAdapter) adaptMSSQLServer(resource *terraform.Block, module *terraform.Module) database.MSSQLServer {
	minTLSVersionVal := iacTypes.StringDefault("", resource.GetMetadata())
	publicAccessVal := iacTypes.BoolDefault(true, resource.GetMetadata())
	enableSSLEnforcementVal := iacTypes.BoolDefault(false, resource.GetMetadata())

	var auditingPolicies []database.ExtendedAuditingPolicy
	var alertPolicies []database.SecurityAlertPolicy
	var firewallRules []database.FirewallRule

	if resource.TypeLabel() == "azurerm_mssql_server" {
		minTLSVersionAttr := resource.GetAttribute("minimum_tls_version")
		minTLSVersionVal = minTLSVersionAttr.AsStringValueOrDefault("", resource)

		publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
		publicAccessVal = publicAccessAttr.AsBoolValueOrDefault(true, resource)

	}

	alertPolicyBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_security_alert_policy", "server_name")
	for _, alertBlock := range alertPolicyBlocks {
		a.alertPolicyIDs.Resolve(alertBlock.ID())
		alertPolicies = append(alertPolicies, adaptMSSQLSecurityAlertPolicy(alertBlock))
	}

	auditingPoliciesBlocks := module.GetReferencingResources(resource, "azurerm_mssql_server_extended_auditing_policy", "server_id")
	if resource.HasChild("extended_auditing_policy") {
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, resource.GetBlocks("extended_auditing_policy")...)
	}

	databasesRes := module.GetReferencingResources(resource, "azurerm_mssql_database", "server_id")
	for _, databaseRes := range databasesRes {
		dbAuditingBlocks := module.GetReferencingResources(databaseRes, "azurerm_mssql_database_extended_auditing_policy", "database_id")
		auditingPoliciesBlocks = append(auditingPoliciesBlocks, dbAuditingBlocks...)
	}

	for _, auditBlock := range auditingPoliciesBlocks {
		a.auditingPolicyIDs.Resolve(auditBlock.ID())
		auditingPolicies = append(auditingPolicies, adaptMSSQLExtendedAuditingPolicy(auditBlock))
	}

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_sql_firewall_rule", "server_name")
	firewallRuleBlocks = append(firewallRuleBlocks, module.GetReferencingResources(resource, "azurerm_mssql_firewall_rule", "server_id")...)
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
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
		ExtendedAuditingPolicies: auditingPolicies,
		SecurityAlertPolicies:    alertPolicies,
	}
}

func (a *mysqlAdapter) adaptMySQLServer(resource *terraform.Block, module *terraform.Module) database.MySQLServer {
	var firewallRules []database.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLSEnforcementDisabled", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mysql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
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

func (a *mariaDBAdapter) adaptMariaDBServer(resource *terraform.Block, module *terraform.Module) database.MariaDBServer {
	var firewallRules []database.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mariadb_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MariaDBServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         iacTypes.StringDefault("", resource.GetMetadata()),
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
	}
}

func (a *postgresqlAdapter) adaptPostgreSQLServer(resource *terraform.Block, module *terraform.Module) database.PostgreSQLServer {
	var firewallRules []database.FirewallRule

	enableSSLEnforcementAttr := resource.GetAttribute("ssl_enforcement_enabled")
	enableSSLEnforcementVal := enableSSLEnforcementAttr.AsBoolValueOrDefault(false, resource)

	minTLSVersionAttr := resource.GetAttribute("ssl_minimal_tls_version_enforced")
	minTLSVersionVal := minTLSVersionAttr.AsStringValueOrDefault("TLSEnforcementDisabled", resource)

	publicAccessAttr := resource.GetAttribute("public_network_access_enabled")
	publicAccessVal := publicAccessAttr.AsBoolValueOrDefault(true, resource)

	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		a.firewallIDs.Resolve(firewallBlock.ID())
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	configBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_configuration", "server_name")
	config := adaptPostgreSQLConfig(resource, configBlocks)

	return database.PostgreSQLServer{
		Metadata: resource.GetMetadata(),
		Server: database.Server{
			Metadata:                  resource.GetMetadata(),
			EnableSSLEnforcement:      enableSSLEnforcementVal,
			MinimumTLSVersion:         minTLSVersionVal,
			EnablePublicNetworkAccess: publicAccessVal,
			FirewallRules:             firewallRules,
		},
		Config: config,
	}
}

func adaptPostgreSQLConfig(resource *terraform.Block, configBlocks []*terraform.Block) database.PostgresSQLConfig {
	config := database.PostgresSQLConfig{
		Metadata:             resource.GetMetadata(),
		LogCheckpoints:       iacTypes.BoolDefault(false, resource.GetMetadata()),
		ConnectionThrottling: iacTypes.BoolDefault(false, resource.GetMetadata()),
		LogConnections:       iacTypes.BoolDefault(false, resource.GetMetadata()),
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

package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
)

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

func adaptMySQLServer(resource *terraform.Block, module *terraform.Module) database.MySQLServer {
	var firewallRules []database.FirewallRule
	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_mysql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	return database.MySQLServer{
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
	}
}

func adaptMySQLFlexibleServer(resource *terraform.Block, module *terraform.Module) database.MySQLServer {
	var firewallRules []database.FirewallRule

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
			Metadata:             resource.GetMetadata(),
			EnableSSLEnforcement: params.requireSecureTransport,
			MinimumTLSVersion:    params.tlsVersion,
			EnablePublicNetworkAccess: resource.GetAttribute("public_network_access_enabled").
				AsBoolValueOrDefault(true, resource),
			FirewallRules: firewallRules,
		},
	}
}

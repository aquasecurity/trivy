package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

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

func adaptPostgreSQLServer(resource *terraform.Block, module *terraform.Module) database.PostgreSQLServer {
	var firewallRules []database.FirewallRule
	firewallRuleBlocks := module.GetReferencingResources(resource, "azurerm_postgresql_firewall_rule", "server_name")
	for _, firewallBlock := range firewallRuleBlocks {
		firewallRules = append(firewallRules, adaptFirewallRule(firewallBlock))
	}

	configs := module.GetReferencingResources(resource, "azurerm_postgresql_configuration", "server_name")
	config := adaptPostgreSQLConfig(resource, configs)
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
		ThreatDetectionPolicy: adaptThreatDetectionPolicy(resource, resource.GetMetadata()),
	}
}

func adaptPostgreSQLFlexibleServer(resource *terraform.Block, module *terraform.Module) database.PostgreSQLServer {
	var firewallRules []database.FirewallRule

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

		// Threat Detection is not configurable via Terraform for PostgreSQL Flexible Server
		// It can only be configured via Azure CLI, so we mark it as unmanaged to avoid false positives
		ThreatDetectionPolicy: database.ThreatDetectionPolicy{
			Metadata: iacTypes.NewUnmanagedMetadata(),
		},
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

		switch {
		case nameAttr.Equals("log_checkpoints"):
			config.LogCheckpoints = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		case nameAttr.Equals("connection_throttling"):
			config.ConnectionThrottling = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		case nameAttr.Equals("log_connections"):
			config.LogConnections = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		case nameAttr.Equals("log_disconnections"):
			config.LogDisconnections = iacTypes.Bool(valAttr.Equals("on"), valAttr.GetMetadata())
		}
	}

	return config
}

func adaptThreatDetectionPolicy(resource *terraform.Block, defaultMetadata iacTypes.Metadata) database.ThreatDetectionPolicy {
	block := resource.GetBlock("threat_detection_policy")
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

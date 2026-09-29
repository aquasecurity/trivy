package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptMariaDBServers(modules terraform.Modules) []database.MariaDBServer {
	var mariaDBServers []database.MariaDBServer
	for _, module := range modules {
		for _, resource := range module.GetResourcesByType("azurerm_mariadb_server") {
			mariaDBServers = append(mariaDBServers, adaptMariaDBServer(resource, module))
		}
	}

	return mariaDBServers
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

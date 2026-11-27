package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const firewallRuleType = "firewallRules"

// adaptFirewallRules collects the firewall rules of a database server from its
// firewallRules child resources, e.g. "Microsoft.Sql/servers/firewallRules".
// https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/firewallrules?pivots=deployment-language-arm-template
func adaptFirewallRules(server azure.Resource, deployment azure.Deployment) []database.FirewallRule {
	return adaptFirewallRuleResources(deployment.GetChildResources(server, firewallRuleType))
}

// orphanFirewallRules returns the top-level firewall rules of serverType whose
// server is unknown.
func orphanFirewallRules(deployment azure.Deployment, serverType string) []database.FirewallRule {
	return adaptFirewallRuleResources(deployment.GetOrphanResources(serverType, firewallRuleType))
}

// orphanage holds firewall rules whose server is unknown.
func orphanage(rules []database.FirewallRule) database.Server {
	metadata := iacTypes.NewUnmanagedMetadata()
	return database.Server{
		Metadata:                  metadata,
		EnableSSLEnforcement:      iacTypes.BoolDefault(false, metadata),
		MinimumTLSVersion:         iacTypes.StringDefault("", metadata),
		EnablePublicNetworkAccess: iacTypes.BoolDefault(false, metadata),
		FirewallRules:             rules,
	}
}

func adaptFirewallRuleResources(resources []azure.Resource) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, resource := range resources {
		rules = append(rules, database.FirewallRule{
			Metadata: resource.Metadata,
			StartIP:  resource.Properties.GetMapValue("startIpAddress").AsStringValue("", resource.Metadata),
			EndIP:    resource.Properties.GetMapValue("endIpAddress").AsStringValue("", resource.Metadata),
		})
	}
	return rules
}

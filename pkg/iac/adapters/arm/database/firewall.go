package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const firewallRuleType = "firewallRules"

// addFirewallRule collects the firewall rules of a database server from the
// firewallRules property and from its firewallRules child resources, e.g.
// "Microsoft.Sql/servers/firewallRules".
// https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/firewallrules?pivots=deployment-language-arm-template
func addFirewallRule(server azure.Resource, deployment azure.Deployment) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, rule := range server.Properties.GetMapValue("firewallRules").AsMap() {
		rules = append(rules, adaptFirewallRule(rule, rule.GetMetadata()))
	}
	return append(rules, adaptFirewallRuleResources(deployment.GetChildResources(server, firewallRuleType))...)
}

// orphanFirewallRules returns the top-level firewall rules of serverType whose
// server is unknown.
func orphanFirewallRules(deployment azure.Deployment, serverType string) []database.FirewallRule {
	return adaptFirewallRuleResources(deployment.GetOrphanResources(serverType, firewallRuleType))
}

// orphanage holds firewall rules whose server is unknown.
func orphanage(metadata iacTypes.Metadata, rules []database.FirewallRule) database.Server {
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
		rules = append(rules, adaptFirewallRule(resource.Properties, resource.Metadata))
	}
	return rules
}

func adaptFirewallRule(properties azure.Value, metadata iacTypes.Metadata) database.FirewallRule {
	return database.FirewallRule{
		Metadata: metadata,
		StartIP:  properties.GetMapValue("startIpAddress").AsStringValue("", metadata),
		EndIP:    properties.GetMapValue("endIpAddress").AsStringValue("", metadata),
	}
}

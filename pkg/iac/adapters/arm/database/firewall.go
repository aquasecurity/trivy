package database

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// addFirewallRule collects the firewall rules of a database server from the
// firewallRules property, child resources, and top-level "<server type>/firewallRules"
// resources, e.g. "Microsoft.Sql/servers/firewallRules".
// https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/firewallrules?pivots=deployment-language-arm-template
func addFirewallRule(server azure.Resource, deployment azure.Deployment) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, rule := range server.Properties.GetMapValue("firewallRules").AsMap() {
		rules = append(rules, adaptFirewallRule(rule, rule.GetMetadata()))
	}

	ruleType := server.Type.AsString() + "/firewallRules"
	for _, typ := range []string{"firewallRules", ruleType} {
		for _, resource := range server.GetResourcesByType(typ) {
			rules = append(rules, adaptFirewallRule(resource.Properties, resource.Metadata))
		}
	}
	for _, resource := range deployment.GetResourcesByType(ruleType) {
		if belongsToServer(resource, server) {
			rules = append(rules, adaptFirewallRule(resource.Properties, resource.Metadata))
		}
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

// belongsToServer reports whether a top-level firewall rule belongs to server.
// The name of such a rule is "<server name>/<rule name>". When either name is an
// expression, which the parser does not evaluate, the rule is kept.
func belongsToServer(rule, server azure.Resource) bool {
	ruleName, serverName := rule.Name.AsString(), server.Name.AsString()
	if ruleName == "" || serverName == "" {
		return true
	}
	parent, _, found := strings.Cut(ruleName, "/")
	return !found || strings.EqualFold(parent, serverName)
}

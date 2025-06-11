package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
)

// TODO: This is the "Microsoft.Sql/servers/firewallRules" resource
// https://learn.microsoft.com/en-us/azure/templates/microsoft.sql/servers/firewallrules?pivots=deployment-language-arm-template
func addFirewallRule(resource azure.Resource) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, rule := range resource.Properties.GetMapValue("firewallRules").AsMap() {
		rules = append(rules, database.FirewallRule{
			Metadata: rule.Metadata,
			StartIP:  rule.GetMapValue("startIpAddress").AsStringValue("", rule.Metadata),
			EndIP:    rule.GetMapValue("endIpAddress").AsStringValue("", rule.Metadata),
		})
	}
	return rules
}

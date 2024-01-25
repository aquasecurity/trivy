package database

import (
	"github.com/aquasecurity/trivy/pkg/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/scanners/azure"
)

func addFirewallRule(resource azure.Resource) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, rule := range resource.Properties.GetMapValue("firewallRules").AsMap() {
		rules = append(rules, database.FirewallRule{
			Metadata: rule.MisconfigMetadata,
			StartIP:  rule.GetMapValue("startIpAddress").AsStringValue("", rule.MisconfigMetadata),
			EndIP:    rule.GetMapValue("endIpAddress").AsStringValue("", rule.MisconfigMetadata),
		})
	}
	return rules
}

package database

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	mysqlFlexibleServerType              = "Microsoft.DBforMySQL/flexibleServers"
	postgresqlFlexibleServerType         = "Microsoft.DBforPostgreSQL/flexibleServers"
	firewallRulesType                    = "firewallRules"
	configurationsType                   = "configurations"
	advancedThreatProtectionSettingsType = "advancedThreatProtectionSettings"
	defaultFlexibleTLSVersion            = "TLS1_2"
)

// flexibleServerParameters represents server configuration parameters that are
// common to both MySQL and PostgreSQL flexible servers in Azure.
type flexibleServerParameters struct {
	requireSecureTransport iacTypes.BoolValue
	tlsVersion             iacTypes.StringValue
}

func parseFlexibleServerParameters(configs []azure.Resource, resourceMetadata iacTypes.Metadata, tlsVersionParam string) flexibleServerParameters {
	// Flexible servers enforce TLS 1.2 by default.
	// https://learn.microsoft.com/en-us/azure/mysql/flexible-server/overview#enterprise-grade-security-compliance-and-privacy
	params := flexibleServerParameters{
		requireSecureTransport: iacTypes.BoolDefault(true, resourceMetadata),
		tlsVersion:             iacTypes.StringDefault(defaultFlexibleTLSVersion, resourceMetadata),
	}

	for _, config := range configs {
		paramName := configParamName(config.Name.AsString())
		val := config.Properties.GetMapValue("value")
		switch {
		case strings.EqualFold(paramName, "require_secure_transport"):
			if parsed, ok := parseBoolConfigValue(val); ok {
				params.requireSecureTransport = parsed
			}
		case strings.EqualFold(paramName, tlsVersionParam):
			if val.Kind == azure.KindString && val.AsString() != "" {
				params.tlsVersion = iacTypes.String(common.MinimumAzureTLSVersion(val.AsString()), val.GetMetadata())
			}
		}
	}

	return params
}

func adaptFlexibleFirewallRules(resources []azure.Resource) []database.FirewallRule {
	var rules []database.FirewallRule
	for _, rule := range resources {
		rules = append(rules, database.FirewallRule{
			Metadata: rule.Metadata,
			StartIP:  rule.Properties.GetMapValue("startIpAddress").AsStringValue("", rule.Metadata),
			EndIP:    rule.Properties.GetMapValue("endIpAddress").AsStringValue("", rule.Metadata),
		})
	}
	return rules
}

func orphanFlexibleServer(firewallRules []database.FirewallRule) database.Server {
	metadata := iacTypes.NewUnmanagedMetadata()
	return database.Server{
		Metadata:                  metadata,
		EnableSSLEnforcement:      iacTypes.BoolDefault(true, metadata),
		MinimumTLSVersion:         iacTypes.StringDefault(defaultFlexibleTLSVersion, metadata),
		EnablePublicNetworkAccess: iacTypes.BoolDefault(false, metadata),
		FirewallRules:             firewallRules,
	}
}

func adaptFlexibleServerPublicNetworkAccess(resource azure.Resource) iacTypes.BoolValue {
	network := resource.Properties.GetMapValue("network")
	if parsed, ok := parseBoolConfigValue(network.GetMapValue("publicNetworkAccess")); ok {
		return parsed
	}
	// When delegatedSubnetResourceId is configured without an explicit publicNetworkAccess value,
	// Azure deploys the flexible server with private access (VNet integration).
	if subnet := network.GetMapValue("delegatedSubnetResourceId"); !subnet.IsNull() && (subnet.Kind != azure.KindString || subnet.AsString() != "") {
		return iacTypes.BoolDefault(false, subnet.GetMetadata())
	}
	return iacTypes.BoolDefault(true, resource.Metadata)
}

func configParamName(name string) string {
	return name[strings.LastIndex(name, "/")+1:]
}

func parseBoolConfigValue(val azure.Value) (iacTypes.BoolValue, bool) {
	switch val.Kind {
	case azure.KindBoolean:
		return val.AsBoolValue(false, val.GetMetadata()), true
	case azure.KindString:
		if val.AsString() == "" {
			return iacTypes.BoolValue{}, false
		}
		return val.AsBoolValue(false, val.GetMetadata()), true
	default:
		return iacTypes.BoolValue{}, false
	}
}

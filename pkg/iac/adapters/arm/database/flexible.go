package database

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const (
	mysqlFlexibleServerType      = "Microsoft.DBforMySQL/flexibleServers"
	postgresqlFlexibleServerType = "Microsoft.DBforPostgreSQL/flexibleServers"
	firewallRulesType            = "firewallRules"
	configurationsType           = "configurations"
	defaultFlexibleTLSVersion    = "TLS1_2"
)

// Flexible servers report the minimum TLS version in the Azure parameter format,
// e.g. TLSv1.2, while single servers and the checks use the TLS1_2 format.
var flexibleTLSVersions = map[string]string{
	"tlsv1":   "TLS1_0",
	"tlsv1.0": "TLS1_0",
	"tlsv1.1": "TLS1_1",
	"tlsv1.2": "TLS1_2",
	"tlsv1.3": "TLS1_3",
}

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
				params.tlsVersion = iacTypes.String(minimumTLSVersion(val.AsString()), val.GetMetadata())
			}
		}
	}

	return params
}

// minimumTLSVersion converts an Azure TLS version to the TLS1_2 format.
// MySQL flexible servers accept a comma-separated list of allowed versions,
// in which case the lowest one is returned. Unrecognized versions are skipped,
// and the value is left as is if none of them is recognized.
func minimumTLSVersion(val string) string {
	var minimum string
	for version := range strings.SplitSeq(val, ",") {
		normalized, ok := flexibleTLSVersions[strings.ToLower(strings.TrimSpace(version))]
		if !ok {
			continue
		}
		if minimum == "" || normalized < minimum {
			minimum = normalized
		}
	}

	if minimum == "" {
		return val
	}

	return minimum
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

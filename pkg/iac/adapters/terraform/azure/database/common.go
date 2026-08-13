package database

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const defaultTLSVersion = "TLS1_2"

// Flexible servers report the minimum TLS version in the Azure parameter format,
// e.g. TLSv1.2, while single servers and the checks use the TLS1_2 format.
var tlsVersions = map[string]string{
	"tlsv1":   "TLS1_0",
	"tlsv1.0": "TLS1_0",
	"tlsv1.1": "TLS1_1",
	"tlsv1.2": "TLS1_2",
	"tlsv1.3": "TLS1_3",
}

// serverParameters represents server configuration parameters that are common
// to both MySQL and PostgreSQL flexible servers in Azure.
type serverParameters struct {
	requireSecureTransport iacTypes.BoolValue
	tlsVersion             iacTypes.StringValue
}

// parseServerParameters parses a list of server configurations to extract
// server parameters for MySQL and PostgreSQL flexible servers.
// The minimum TLS version is set by a different parameter for each engine,
// so its name is passed by the caller.
func parseServerParameters(configs []*terraform.Block, resourceMetadata iacTypes.Metadata, tlsVersionParam string) serverParameters {
	// https://learn.microsoft.com/en-us/azure/mysql/flexible-server/overview#enterprise-grade-security-compliance-and-privacy
	params := serverParameters{
		requireSecureTransport: iacTypes.BoolDefault(true, resourceMetadata),
		tlsVersion:             iacTypes.StringDefault(defaultTLSVersion, resourceMetadata),
	}

	for _, config := range configs {
		nameAttr := config.GetAttribute("name")
		valAttr := config.GetAttribute("value")
		switch {
		case nameAttr.Equals("require_secure_transport"):
			params.requireSecureTransport, _ = iacTypes.BoolFromCtyValue(valAttr.Value(), valAttr.GetMetadata())
		case nameAttr.Equals(tlsVersionParam):
			val := valAttr.AsStringValueOrDefault(defaultTLSVersion, config)
			params.tlsVersion = iacTypes.String(minimumTLSVersion(val.Value()), val.GetMetadata())
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
		normalized, ok := tlsVersions[strings.ToLower(strings.TrimSpace(version))]
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

func adaptFirewallRule(resource *terraform.Block) database.FirewallRule {
	return database.FirewallRule{
		Metadata: resource.GetMetadata(),
		StartIP: resource.GetAttribute("start_ip_address").
			AsStringValueOrDefault("", resource),
		EndIP: resource.GetAttribute("end_ip_address").
			AsStringValueOrDefault("", resource),
	}
}

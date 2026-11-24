package database

import (
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const defaultTLSVersion = "TLS1_2"

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
			params.tlsVersion = iacTypes.String(common.MinimumAzureTLSVersion(val.Value()), val.GetMetadata())
		}
	}

	return params
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

package database

import (
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

// serverParameters represents server configuration parameters that are common
// to both MySQL and PostgreSQL flexible servers in Azure.
type serverParameters struct {
	requireSecureTransport iacTypes.BoolValue
	tlsVersion             iacTypes.StringValue
}

// parseServerParameters parses a list of server configurations to extract
// server parameters for MySQL and PostgreSQL flexible servers.
func parseServerParameters(configs []*terraform.Block, resourceMetadata iacTypes.Metadata) serverParameters {
	// https://learn.microsoft.com/en-us/azure/mysql/flexible-server/overview#enterprise-grade-security-compliance-and-privacy
	params := serverParameters{
		requireSecureTransport: iacTypes.BoolDefault(true, resourceMetadata),
		tlsVersion:             iacTypes.StringDefault("TLS1_2", resourceMetadata),
	}

	for _, config := range configs {
		nameAttr := config.GetAttribute("name")
		valAttr := config.GetAttribute("value")
		switch {
		case nameAttr.Equals("require_secure_transport"):
			params.requireSecureTransport, _ = iacTypes.BoolFromCtyValue(valAttr.Value(), valAttr.GetMetadata())
		case nameAttr.Equals("tls_version"), nameAttr.Equals("ssl_min_protocol_version"):
			params.tlsVersion = normalizeTLSVersion(valAttr.AsStringValueOrDefault("TLS1_2", config))
		}
	}

	return params
}

// normalizeTLSVersion converts the TLS version spelling accepted by Azure
// ("TLSv1.2", "TLSv1.3") to the form expected by the azure-database-secure-
// tls-policy check ("TLS1_2", "TLS1_3").
func normalizeTLSVersion(version iacTypes.StringValue) iacTypes.StringValue {
	normalized := strings.ReplaceAll(version.Value(), "TLSv", "TLS")
	normalized = strings.ReplaceAll(normalized, ".", "_")
	return iacTypes.String(normalized, version.GetMetadata())
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

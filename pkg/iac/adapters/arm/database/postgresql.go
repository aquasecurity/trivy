package database

import (
	"fmt"
	"strings"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func adaptPostgreSQLServers(deployment azure.Deployment) (databases []database.PostgreSQLServer) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.DBforPostgreSQL/servers") {
		databases = append(databases, adaptPostgreSQLServer(resource, deployment))
	}
	for _, resource := range deployment.GetResourcesByType(postgresqlFlexibleServerType) {
		databases = append(databases, adaptPostgreSQLFlexibleServer(resource, deployment))
	}

	return databases
}

func adaptPostgreSQLFlexibleServer(resource azure.Resource, deployment azure.Deployment) database.PostgreSQLServer {
	firewallRules := adaptFlexibleFirewallRules(deployment.GetChildResources(resource, firewallRulesType))
	configs := deployment.GetChildResources(resource, configurationsType)
	params := parseFlexibleServerParameters(configs, resource.Metadata, "ssl_min_protocol_version")

	geoRedundantBackup := resource.Properties.GetMapValue("backup").GetMapValue("geoRedundantBackup")
	geoRedundantBackupEnabled := iacTypes.BoolDefault(false, resource.Metadata)
	if parsed, ok := parseBoolConfigValue(geoRedundantBackup); ok {
		geoRedundantBackupEnabled = parsed
	}

	return database.PostgreSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      params.requireSecureTransport,
			MinimumTLSVersion:         params.tlsVersion,
			EnablePublicNetworkAccess: adaptFlexibleServerPublicNetworkAccess(resource),
			FirewallRules:             firewallRules,
		},
		Config:                    adaptPostgreSQLFlexibleConfiguration(resource.Metadata, configs),
		GeoRedundantBackupEnabled: geoRedundantBackupEnabled,
		ThreatDetectionPolicy: database.ThreatDetectionPolicy{
			Metadata: iacTypes.NewUnmanagedMetadata(),
		},
	}
}

func adaptPostgreSQLFlexibleConfiguration(metadata iacTypes.Metadata, configs []azure.Resource) database.PostgresSQLConfig {
	config := database.PostgresSQLConfig{
		Metadata:             metadata,
		LogCheckpoints:       iacTypes.BoolDefault(false, metadata),
		ConnectionThrottling: iacTypes.BoolDefault(false, metadata),
		LogConnections:       iacTypes.BoolDefault(false, metadata),
		LogDisconnections:    iacTypes.BoolDefault(false, metadata),
	}

	for _, configuration := range configs {
		paramName := configParamName(configuration.Name.AsString())
		parsed, ok := parseBoolConfigValue(configuration.Properties.GetMapValue("value"))
		if !ok {
			continue
		}
		switch {
		case strings.EqualFold(paramName, "log_checkpoints"):
			config.LogCheckpoints = parsed
		case strings.EqualFold(paramName, "log_connections"):
			config.LogConnections = parsed
		case strings.EqualFold(paramName, "connection_throttle.enable"):
			config.ConnectionThrottling = parsed
		case strings.EqualFold(paramName, "log_disconnections"):
			config.LogDisconnections = parsed
		}
	}

	return config
}

func adaptPostgreSQLServer(resource azure.Resource, deployment azure.Deployment) database.PostgreSQLServer {
	properties := resource.Properties
	geoRedundantBackup := properties.GetMapValue("storageProfile").GetMapValue("geoRedundantBackup")
	geoRedundantBackupEnabled := geoRedundantBackup.AsStringValue("Disabled", resource.Metadata)

	threatDetectionPolicy := adaptThreatDetectionPolicy(resource, deployment)

	return database.PostgreSQLServer{
		Metadata: resource.Metadata,
		Server: database.Server{
			Metadata:                  resource.Metadata,
			EnableSSLEnforcement:      properties.GetMapValue("sslEnforcement").AsBoolValue(false, resource.Metadata),
			MinimumTLSVersion:         properties.GetMapValue("minimalTlsVersion").AsStringValue("TLSEnforcementDisabled", resource.Metadata),
			EnablePublicNetworkAccess: properties.GetMapValue("publicNetworkAccess").AsBoolValue(false, resource.Metadata),
			FirewallRules:             addFirewallRule(resource),
		},
		Config:                    adaptPostgreSQLConfiguration(resource, deployment),
		GeoRedundantBackupEnabled: iacTypes.Bool(geoRedundantBackupEnabled.EqualTo("Enabled"), geoRedundantBackup.GetMetadata()),
		ThreatDetectionPolicy:     threatDetectionPolicy,
	}
}

func adaptPostgreSQLConfiguration(resource azure.Resource, deployment azure.Deployment) database.PostgresSQLConfig {

	parent := fmt.Sprintf("%s/", resource.Name.AsString())

	config := database.PostgresSQLConfig{
		Metadata:             resource.Metadata,
		LogCheckpoints:       iacTypes.BoolDefault(false, resource.Metadata),
		ConnectionThrottling: iacTypes.BoolDefault(false, resource.Metadata),
		LogConnections:       iacTypes.BoolDefault(false, resource.Metadata),
		LogDisconnections:    iacTypes.BoolDefault(false, resource.Metadata),
	}

	for _, configuration := range deployment.GetResourcesByType("Microsoft.DBforPostgreSQL/servers/configurations") {
		if !strings.HasPrefix(configuration.Name.AsString(), parent) {
			continue
		}
		val := configuration.Properties.GetMapValue("value")
		if strings.HasSuffix(configuration.Name.AsString(), "log_checkpoints") {
			config.LogCheckpoints = val.AsBoolValue(false, configuration.Metadata)
			continue
		}
		if strings.HasSuffix(configuration.Name.AsString(), "log_connections") {
			config.LogConnections = val.AsBoolValue(false, configuration.Metadata)
			continue
		}
		if strings.HasSuffix(configuration.Name.AsString(), "connection_throttling") {
			config.ConnectionThrottling = val.AsBoolValue(false, configuration.Metadata)
			continue
		}
		if strings.HasSuffix(configuration.Name.AsString(), "log_disconnections") {
			config.LogDisconnections = val.AsBoolValue(false, configuration.Metadata)
			continue
		}
	}

	return config
}

func adaptThreatDetectionPolicy(resource azure.Resource, deployment azure.Deployment) database.ThreatDetectionPolicy {
	// Threat detection policy is configured via Microsoft.DBforPostgreSQL/servers/securityAlertPolicies
	// This is a separate child resource, not a property of the server resource
	parent := fmt.Sprintf("%s/", resource.Name.AsString())

	enabled := false
	metadata := resource.Metadata

	// Look for security alert policy resources that belong to this server
	for _, policy := range deployment.GetResourcesByType("Microsoft.DBforPostgreSQL/servers/securityAlertPolicies") {
		if !strings.HasPrefix(policy.Name.AsString(), parent) {
			continue
		}
		// Found the security alert policy for this server
		state := policy.Properties.GetMapValue("state").AsStringValue("Disabled", policy.Metadata)
		enabled = state.EqualTo("Enabled")
		metadata = policy.Properties.GetMapValue("state").GetMetadata()
		break
	}

	return database.ThreatDetectionPolicy{
		Metadata: metadata,
		Enabled:  iacTypes.Bool(enabled, metadata),
	}
}

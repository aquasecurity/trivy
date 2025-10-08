package database

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Database struct {
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	Metadata iacTypes.Metadata
	Server
}

type MySQLServer struct {
	Metadata iacTypes.Metadata
	Server
}

type PostgreSQLServer struct {
	Metadata iacTypes.Metadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	Metadata             iacTypes.Metadata
	LogCheckpoints       iacTypes.BoolValue
	ConnectionThrottling iacTypes.BoolValue
	LogConnections       iacTypes.BoolValue
}

type Server struct {
	Metadata                  iacTypes.Metadata
	EnableSSLEnforcement      iacTypes.BoolValue
	MinimumTLSVersion         iacTypes.StringValue
	EnablePublicNetworkAccess iacTypes.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	Metadata iacTypes.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	Metadata           iacTypes.Metadata
	EmailAddresses     []iacTypes.StringValue
	DisabledAlerts     []iacTypes.StringValue
	EmailAccountAdmins iacTypes.BoolValue
}

type ExtendedAuditingPolicy struct {
	Metadata        iacTypes.Metadata
	RetentionInDays iacTypes.IntValue
}

type FirewallRule struct {
	Metadata iacTypes.Metadata
	StartIP  iacTypes.StringValue
	EndIP    iacTypes.StringValue
}

package database

import "github.com/aquasecurity/defsec/parsers/types"

type Database struct {
	types.Metadata
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	types.Metadata
	Server
}

type MySQLServer struct {
	types.Metadata
	Server
}

type PostgreSQLServer struct {
	types.Metadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	types.Metadata
	LogCheckpoints       types.BoolValue
	ConnectionThrottling types.BoolValue
	LogConnections       types.BoolValue
}

type Server struct {
	types.Metadata
	EnableSSLEnforcement      types.BoolValue
	MinimumTLSVersion         types.StringValue
	EnablePublicNetworkAccess types.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	types.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	types.Metadata
	EmailAddresses     []types.StringValue
	DisabledAlerts     []types.StringValue
	EmailAccountAdmins types.BoolValue
}

type ExtendedAuditingPolicy struct {
	types.Metadata
	RetentionInDays types.IntValue
}

type FirewallRule struct {
	types.Metadata
	StartIP types.StringValue
	EndIP   types.StringValue
}

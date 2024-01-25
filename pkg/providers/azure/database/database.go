package database

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Database struct {
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	Metadata defsecTypes.MisconfigMetadata
	Server
}

type MySQLServer struct {
	Metadata defsecTypes.MisconfigMetadata
	Server
}

type PostgreSQLServer struct {
	Metadata defsecTypes.MisconfigMetadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	Metadata             defsecTypes.MisconfigMetadata
	LogCheckpoints       defsecTypes.BoolValue
	ConnectionThrottling defsecTypes.BoolValue
	LogConnections       defsecTypes.BoolValue
}

type Server struct {
	Metadata                  defsecTypes.MisconfigMetadata
	EnableSSLEnforcement      defsecTypes.BoolValue
	MinimumTLSVersion         defsecTypes.StringValue
	EnablePublicNetworkAccess defsecTypes.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	Metadata defsecTypes.MisconfigMetadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	Metadata           defsecTypes.MisconfigMetadata
	EmailAddresses     []defsecTypes.StringValue
	DisabledAlerts     []defsecTypes.StringValue
	EmailAccountAdmins defsecTypes.BoolValue
}

type ExtendedAuditingPolicy struct {
	Metadata        defsecTypes.MisconfigMetadata
	RetentionInDays defsecTypes.IntValue
}

type FirewallRule struct {
	Metadata defsecTypes.MisconfigMetadata
	StartIP  defsecTypes.StringValue
	EndIP    defsecTypes.StringValue
}

package database

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Database struct {
	MSSQLServers      []MSSQLServer
	MariaDBServers    []MariaDBServer
	MySQLServers      []MySQLServer
	PostgreSQLServers []PostgreSQLServer
}

type MariaDBServer struct {
	Metadata defsecTypes.Metadata
	Server
}

type MySQLServer struct {
	Metadata defsecTypes.Metadata
	Server
}

type PostgreSQLServer struct {
	Metadata defsecTypes.Metadata
	Server
	Config PostgresSQLConfig
}

type PostgresSQLConfig struct {
	Metadata             defsecTypes.Metadata
	LogCheckpoints       defsecTypes.BoolValue
	ConnectionThrottling defsecTypes.BoolValue
	LogConnections       defsecTypes.BoolValue
}

type Server struct {
	Metadata                  defsecTypes.Metadata
	EnableSSLEnforcement      defsecTypes.BoolValue
	MinimumTLSVersion         defsecTypes.StringValue
	EnablePublicNetworkAccess defsecTypes.BoolValue
	FirewallRules             []FirewallRule
}

type MSSQLServer struct {
	Metadata defsecTypes.Metadata
	Server
	ExtendedAuditingPolicies []ExtendedAuditingPolicy
	SecurityAlertPolicies    []SecurityAlertPolicy
}

type SecurityAlertPolicy struct {
	Metadata           defsecTypes.Metadata
	EmailAddresses     []defsecTypes.StringValue
	DisabledAlerts     []defsecTypes.StringValue
	EmailAccountAdmins defsecTypes.BoolValue
}

type ExtendedAuditingPolicy struct {
	Metadata        defsecTypes.Metadata
	RetentionInDays defsecTypes.IntValue
}

type FirewallRule struct {
	Metadata defsecTypes.Metadata
	StartIP  defsecTypes.StringValue
	EndIP    defsecTypes.StringValue
}

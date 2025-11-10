package database

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected database.Database
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/servers",
      "properties": {}
    },
    {
      "type": "Microsoft.Sql/servers",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforMariaDB/servers",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers",
      "properties": {}
    }
  ]
}`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{{
					Server: database.Server{
						MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
					},
				}},
				MySQLServers: []database.MySQLServer{{
					Server: database.Server{
						MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
					},
				}},
				MariaDBServers: []database.MariaDBServer{{
					Server: database.Server{
						MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
					},
				}},
				PostgreSQLServers: []database.PostgreSQLServer{{
					Server: database.Server{
						MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
					},
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/servers",
      "properties": {
        "sslEnforcement": "Enabled",
        "minimalTlsVersion": "TLS1_2",
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "type": "Microsoft.Sql/servers",
      "properties": {
        "minimalTlsVersion": "TLS1_2",
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "type": "Microsoft.Sql/servers/extendedAuditingSettings",
      "properties": {
        "retentionDays": 100
      }
    },
    {
      "type": "Microsoft.Sql/servers/securityAlertPolicies",
      "properties": {
        "emailAddresses": [
          "foo@bar.io"
        ],
        "disabledAlerts": [
          "Sql_Injection"
        ],
        "emailAccountAdmins": true
      }
    },
    {
      "type": "Microsoft.DBforMariaDB/servers",
      "properties": {
        "sslEnforcement": "Enabled",
        "minimalTlsVersion": "TLS1_2",
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers",
      "name": "foo",
      "properties": {
        "sslEnforcement": "Enabled",
        "minimalTlsVersion": "TLS1_2",
        "publicNetworkAccess": "Enabled"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers/configurations",
      "name": "foo/log_connections",
      "properties": {
        "value": "ON",
        "source": "user-override"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers/configurations",
      "name": "foo/log_checkpoints",
      "properties": {
        "value": "ON",
        "source": "user-override"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers/configurations",
      "name": "foo/connection_throttling",
      "properties": {
        "value": "ON",
        "source": "user-override"
      }
    }
  ]
}`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{{
					Server: database.Server{
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(true),
					},
					ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{{
						RetentionInDays: types.IntTest(100),
					}},
					SecurityAlertPolicies: []database.SecurityAlertPolicy{{
						EmailAddresses:     []types.StringValue{types.StringTest("foo@bar.io")},
						DisabledAlerts:     []types.StringValue{types.StringTest("Sql_Injection")},
						EmailAccountAdmins: types.BoolTest(true),
					}},
				}},
				MySQLServers: []database.MySQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(true),
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(true),
					},
				}},
				MariaDBServers: []database.MariaDBServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(true),
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(true),
					},
				}},
				PostgreSQLServers: []database.PostgreSQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(true),
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(true),
					},
					Config: database.PostgresSQLConfig{
						LogCheckpoints:       types.BoolTest(true),
						LogConnections:       types.BoolTest(true),
						ConnectionThrottling: types.BoolTest(true),
					},
				}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}

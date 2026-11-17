package database

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/database"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser"
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
		{
			name: "firewall rules as child resources",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "name": "sql",
      "resources": [
        {
          "type": "firewallRules",
          "name": "all",
          "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}
        },
        {
          "type": "Microsoft.Sql/servers/firewallRules",
          "name": "office",
          "properties": {"startIpAddress": "10.0.0.1", "endIpAddress": "10.0.0.9"}
        }
      ]
    }
  ]
}`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{{
					Server: database.Server{
						MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
						FirewallRules: []database.FirewallRule{
							{StartIP: types.StringTest("0.0.0.0"), EndIP: types.StringTest("255.255.255.255")},
							{StartIP: types.StringTest("10.0.0.1"), EndIP: types.StringTest("10.0.0.9")},
						},
					},
				}},
			},
		},
		{
			name: "top-level firewall rules go to the server they name",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "name": "one"
    },
    {
      "type": "Microsoft.Sql/servers",
      "name": "two"
    },
    {
      "type": "Microsoft.Sql/servers/firewallRules",
      "name": "one/all",
      "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}
    },
    {
      "type": "Microsoft.DBforMySQL/servers",
      "name": "mysql"
    },
    {
      "type": "Microsoft.DBforMySQL/servers/firewallRules",
      "name": "mysql/office",
      "properties": {"startIpAddress": "10.0.0.1", "endIpAddress": "10.0.0.9"}
    }
  ]
}`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Server: database.Server{
							MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
							FirewallRules: []database.FirewallRule{
								{StartIP: types.StringTest("0.0.0.0"), EndIP: types.StringTest("255.255.255.255")},
							},
						},
					},
					{
						Server: database.Server{
							MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
						},
					},
				},
				MySQLServers: []database.MySQLServer{{
					Server: database.Server{
						MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
						FirewallRules: []database.FirewallRule{
							{StartIP: types.StringTest("10.0.0.1"), EndIP: types.StringTest("10.0.0.9")},
						},
					},
				}},
			},
		},
		{
			name: "top-level firewall rule with an expression name goes to the orphan server",
			source: `{
  "parameters": {
    "serverName": {"type": "string", "defaultValue": "one"}
  },
  "resources": [
    {
      "type": "Microsoft.Sql/servers",
      "name": "one"
    },
    {
      "type": "Microsoft.Sql/servers",
      "name": "two"
    },
    {
      "type": "Microsoft.Sql/servers/firewallRules",
      "name": "[concat(parameters('serverName'), '/all')]",
      "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}
    }
  ]
}`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Server: database.Server{
							MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
						},
					},
					{
						Server: database.Server{
							MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
						},
					},
					{
						Server: database.Server{
							FirewallRules: []database.FirewallRule{
								{StartIP: types.StringTest("0.0.0.0"), EndIP: types.StringTest("255.255.255.255")},
							},
						},
					},
				},
			},
		},
		{
			name: "top-level firewall rule goes to the orphan server when the server name is an expression",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/servers",
      "name": "[parameters('serverName')]"
    },
    {
      "type": "Microsoft.DBforPostgreSQL/servers/firewallRules",
      "name": "pg/all",
      "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}
    }
  ]
}`,
			expected: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Server: database.Server{
							MinimumTLSVersion: types.StringTest("TLSEnforcementDisabled"),
						},
					},
					{
						Server: database.Server{
							FirewallRules: []database.FirewallRule{
								{StartIP: types.StringTest("0.0.0.0"), EndIP: types.StringTest("255.255.255.255")},
							},
						},
					},
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}

}

func TestAdaptOrphanServerIsUnmanaged(t *testing.T) {
	fsys := testutil.CreateFS(map[string]string{
		"test.json": `{
  "resources": [
    {
      "type": "Microsoft.Sql/servers/firewallRules",
      "name": "[format('{0}/all', parameters('serverName'))]",
      "properties": {"startIpAddress": "0.0.0.0", "endIpAddress": "255.255.255.255"}
    }
  ]
}`,
	})
	deployments, err := parser.New(fsys).ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, deployments, 1)

	servers := Adapt(deployments[0]).MSSQLServers
	require.Len(t, servers, 1)
	assert.False(t, servers[0].Metadata.IsManaged())
	assert.False(t, servers[0].Server.Metadata.IsManaged())
	require.Len(t, servers[0].FirewallRules, 1)
	assert.True(t, servers[0].FirewallRules[0].Metadata.IsManaged())
}

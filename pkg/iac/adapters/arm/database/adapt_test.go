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
			name: "empty flexible servers use secure TLS defaults and default logging",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "name": "mysql-empty",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "pg-empty",
      "properties": {}
    }
  ]
}`,
			expected: database.Database{
				MySQLServers: []database.MySQLServer{{
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
						LogCheckpoints:    types.BoolTest(true),
						LogConnections:    types.BoolTest(true),
						LogDisconnections: types.BoolTest(true),
					},
				}},
			},
		},
		{
			name: "postgresql flexible server with top-level firewall rule, configurations and threat detection",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "example",
      "properties": {
        "network": {
          "publicNetworkAccess": "Disabled"
        },
        "backup": {
          "geoRedundantBackup": "Enabled"
        }
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
      "name": "example/allow-all",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/require_secure_transport",
      "properties": {
        "value": "ON"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/ssl_min_protocol_version",
      "properties": {
        "value": "TLSv1.3"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/log_checkpoints",
      "properties": {
        "value": "off"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/log_connections",
      "properties": {
        "value": "OFF"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/log_disconnections",
      "properties": {
        "value": "OFF"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/connection_throttle.enable",
      "properties": {
        "value": "on"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/advancedThreatProtectionSettings",
      "name": "example/Default",
      "properties": {
        "state": "Enabled"
      }
    }
  ]
}`,
			expected: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(true),
						MinimumTLSVersion:         types.StringTest("TLS1_3"),
						EnablePublicNetworkAccess: types.BoolTest(false),
						FirewallRules: []database.FirewallRule{{
							StartIP: types.StringTest("0.0.0.0"),
							EndIP:   types.StringTest("255.255.255.255"),
						}},
					},
					Config: database.PostgresSQLConfig{
						LogCheckpoints:       types.BoolTest(false),
						ConnectionThrottling: types.BoolTest(true),
						LogConnections:       types.BoolTest(false),
						LogDisconnections:    types.BoolTest(false),
					},
					GeoRedundantBackupEnabled: types.BoolTest(true),
					ThreatDetectionPolicy: database.ThreatDetectionPolicy{
						Enabled: types.BoolTest(true),
					},
				}},
			},
		},
		{
			name: "postgresql flexible server with nested insecure children",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "pg-nested",
      "properties": {
        "network": {
          "publicNetworkAccess": "Enabled"
        }
      },
      "resources": [
        {
          "type": "firewallRules",
          "name": "allow-all",
          "properties": {
            "startIpAddress": "0.0.0.0",
            "endIpAddress": "255.255.255.255"
          }
        },
        {
          "type": "configurations",
          "name": "require_secure_transport",
          "properties": {
            "value": "OFF"
          }
        },
        {
          "type": "configurations",
          "name": "ssl_min_protocol_version",
          "properties": {
            "value": "TLSv1.1"
          }
        }
      ]
    }
  ]
}`,
			expected: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(false),
						MinimumTLSVersion:         types.StringTest("TLS1_1"),
						EnablePublicNetworkAccess: types.BoolTest(true),
						FirewallRules: []database.FirewallRule{{
							StartIP: types.StringTest("0.0.0.0"),
							EndIP:   types.StringTest("255.255.255.255"),
						}},
					},
					Config: database.PostgresSQLConfig{
						LogCheckpoints:    types.BoolTest(true),
						LogConnections:    types.BoolTest(true),
						LogDisconnections: types.BoolTest(true),
					},
				}},
			},
		},
		{
			name: "mysql flexible server with nested and top-level children and TLS version list",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "name": "mysql-flex",
      "properties": {
        "network": {
          "publicNetworkAccess": "Disabled"
        }
      },
      "resources": [
        {
          "type": "firewallRules",
          "name": "office",
          "properties": {
            "startIpAddress": "40.112.8.12",
            "endIpAddress": "40.112.8.12"
          }
        },
        {
          "type": "configurations",
          "name": "tls_version",
          "properties": {
            "value": "TLSv1.3,TLSv1.2"
          }
        },
        {
          "type": "configurations",
          "name": "interactive_timeout",
          "properties": {
            "value": "600"
          }
        }
      ]
    },
    {
      "type": "Microsoft.DBforMySQL/flexibleServers/firewallRules",
      "name": "mysql-flex/allow-all",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    },
    {
      "type": "Microsoft.DBforMySQL/flexibleServers/configurations",
      "name": "mysql-flex/require_secure_transport",
      "properties": {
        "value": "OFF"
      }
    }
  ]
}`,
			expected: database.Database{
				MySQLServers: []database.MySQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(false),
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(false),
						FirewallRules: []database.FirewallRule{
							{
								StartIP: types.StringTest("40.112.8.12"),
								EndIP:   types.StringTest("40.112.8.12"),
							},
							{
								StartIP: types.StringTest("0.0.0.0"),
								EndIP:   types.StringTest("255.255.255.255"),
							},
						},
					},
				}},
			},
		},
		{
			name: "private access via delegatedSubnetResourceId disables public network access by default",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "name": "mysql-private",
      "properties": {
        "network": {
          "delegatedSubnetResourceId": "/subscriptions/sub/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/db"
        }
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "pg-private",
      "properties": {
        "network": {
          "delegatedSubnetResourceId": "[resourceId('Microsoft.Network/virtualNetworks/subnets', 'vnet', 'db')]"
        }
      }
    }
  ]
}`,
			expected: database.Database{
				MySQLServers: []database.MySQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(true),
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(false),
					},
				}},
				PostgreSQLServers: []database.PostgreSQLServer{{
					Server: database.Server{
						EnableSSLEnforcement:      types.BoolTest(true),
						MinimumTLSVersion:         types.StringTest("TLS1_2"),
						EnablePublicNetworkAccess: types.BoolTest(false),
					},
					Config: database.PostgresSQLConfig{
						LogCheckpoints:    types.BoolTest(true),
						LogConnections:    types.BoolTest(true),
						LogDisconnections: types.BoolTest(true),
					},
				}},
			},
		},
		{
			name: "top-level children go only to their matching server case-insensitively",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "one",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "two",
      "properties": {}
    },
    {
      "type": "microsoft.dbforpostgresql/flexibleservers/firewallrules",
      "name": "TWO/allow-all",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    },
    {
      "type": "microsoft.dbforpostgresql/flexibleservers/configurations",
      "name": "TWO/ssl_min_protocol_version",
      "properties": {
        "value": "TLSv1.1"
      }
    }
  ]
}`,
			expected: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Server: database.Server{
							EnableSSLEnforcement:      types.BoolTest(true),
							MinimumTLSVersion:         types.StringTest("TLS1_2"),
							EnablePublicNetworkAccess: types.BoolTest(true),
						},
						Config: database.PostgresSQLConfig{
							LogCheckpoints:    types.BoolTest(true),
							LogConnections:    types.BoolTest(true),
							LogDisconnections: types.BoolTest(true),
						},
					},
					{
						Server: database.Server{
							EnableSSLEnforcement:      types.BoolTest(true),
							MinimumTLSVersion:         types.StringTest("TLS1_1"),
							EnablePublicNetworkAccess: types.BoolTest(true),
							FirewallRules: []database.FirewallRule{{
								StartIP: types.StringTest("0.0.0.0"),
								EndIP:   types.StringTest("255.255.255.255"),
							}},
						},
						Config: database.PostgresSQLConfig{
							LogCheckpoints:    types.BoolTest(true),
							LogConnections:    types.BoolTest(true),
							LogDisconnections: types.BoolTest(true),
						},
					},
				},
			},
		},
		{
			name: "orphan top-level firewall rules with expression names go to unmanaged flexible servers",
			source: `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers",
      "name": "mysql-one",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforMySQL/flexibleServers/firewallRules",
      "name": "[format('{0}/{1}', parameters('mysqlServerName'), 'allow-all')]",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "[parameters('pgServerName')]",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
      "name": "pg-one/allow-all",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    }
  ]
}`,
			expected: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Server: database.Server{
							EnableSSLEnforcement:      types.BoolTest(true),
							MinimumTLSVersion:         types.StringTest("TLS1_2"),
							EnablePublicNetworkAccess: types.BoolTest(true),
						},
					},
					{
						Server: database.Server{
							EnableSSLEnforcement:      types.BoolTest(true),
							MinimumTLSVersion:         types.StringTest("TLS1_2"),
							EnablePublicNetworkAccess: types.BoolTest(false),
							FirewallRules: []database.FirewallRule{{
								StartIP: types.StringTest("0.0.0.0"),
								EndIP:   types.StringTest("255.255.255.255"),
							}},
						},
					},
				},
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Server: database.Server{
							EnableSSLEnforcement:      types.BoolTest(true),
							MinimumTLSVersion:         types.StringTest("TLS1_2"),
							EnablePublicNetworkAccess: types.BoolTest(true),
						},
						Config: database.PostgresSQLConfig{
							LogCheckpoints:    types.BoolTest(true),
							LogConnections:    types.BoolTest(true),
							LogDisconnections: types.BoolTest(true),
						},
					},
					{
						Server: database.Server{
							EnableSSLEnforcement:      types.BoolTest(true),
							MinimumTLSVersion:         types.StringTest("TLS1_2"),
							EnablePublicNetworkAccess: types.BoolTest(false),
							FirewallRules: []database.FirewallRule{{
								StartIP: types.StringTest("0.0.0.0"),
								EndIP:   types.StringTest("255.255.255.255"),
							}},
						},
						Config: database.PostgresSQLConfig{
							LogCheckpoints:    types.BoolTest(true),
							LogConnections:    types.BoolTest(true),
							LogDisconnections: types.BoolTest(true),
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

func TestAdaptOrphanFlexibleServersAreUnmanaged(t *testing.T) {
	fsys := testutil.CreateFS(map[string]string{
		"test.json": `{
  "resources": [
    {
      "type": "Microsoft.DBforMySQL/flexibleServers/firewallRules",
      "name": "[format('{0}/allow-all', parameters('mysqlName'))]",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
      "name": "[format('{0}/allow-all', parameters('pgName'))]",
      "properties": {
        "startIpAddress": "0.0.0.0",
        "endIpAddress": "255.255.255.255"
      }
    }
  ]
}`,
	})

	deployments, err := parser.New(fsys).ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, deployments, 1)

	adapted := Adapt(deployments[0])
	require.Len(t, adapted.MySQLServers, 1)
	assert.False(t, adapted.MySQLServers[0].Metadata.IsManaged())
	require.Len(t, adapted.MySQLServers[0].FirewallRules, 1)
	assert.True(t, adapted.MySQLServers[0].FirewallRules[0].Metadata.IsManaged())

	require.Len(t, adapted.PostgreSQLServers, 1)
	assert.False(t, adapted.PostgreSQLServers[0].Metadata.IsManaged())
	require.Len(t, adapted.PostgreSQLServers[0].FirewallRules, 1)
	assert.True(t, adapted.PostgreSQLServers[0].FirewallRules[0].Metadata.IsManaged())
}

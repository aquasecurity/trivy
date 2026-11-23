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

func TestAdaptFlexibleServers(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected database.Database
	}{
		{
			name: "empty flexible servers use secure TLS defaults and public access default",
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
				}},
			},
		},
		{
			name: "postgresql flexible server with top-level firewall rule and configurations",
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
        "value": "on"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/log_connections",
      "properties": {
        "value": "ON"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/log_disconnections",
      "properties": {
        "value": "ON"
      }
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/configurations",
      "name": "example/connection_throttle.enable",
      "properties": {
        "value": "on"
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
						LogCheckpoints:       types.BoolTest(true),
						ConnectionThrottling: types.BoolTest(true),
						LogConnections:       types.BoolTest(true),
						LogDisconnections:    types.BoolTest(true),
					},
					GeoRedundantBackupEnabled: types.BoolTest(true),
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

func TestAdaptFlexibleServerMetadata(t *testing.T) {
	fsys := testutil.CreateFS(map[string]string{
		"test.json": `{
  "resources": [
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers",
      "name": "example",
      "properties": {}
    },
    {
      "type": "Microsoft.DBforPostgreSQL/flexibleServers/firewallRules",
      "name": "example/allow-all",
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

	servers := Adapt(deployments[0]).PostgreSQLServers
	require.Len(t, servers, 1)

	assert.True(t, servers[0].Metadata.IsManaged())
	assert.False(t, servers[0].ThreatDetectionPolicy.Metadata.IsManaged())
	require.Len(t, servers[0].FirewallRules, 1)
	assert.True(t, servers[0].FirewallRules[0].Metadata.IsManaged())
}

func Test_minimumTLSVersion(t *testing.T) {
	tests := []struct {
		name     string
		val      string
		expected string
	}{
		{
			name:     "single version",
			val:      "TLSv1.2",
			expected: "TLS1_2",
		},
		{
			name:     "TLSv1 without minor version",
			val:      "TLSv1",
			expected: "TLS1_0",
		},
		{
			name:     "mixed case",
			val:      "tlsV1.3",
			expected: "TLS1_3",
		},
		{
			name:     "list with lowest version last",
			val:      "TLSv1.3,TLSv1.2",
			expected: "TLS1_2",
		},
		{
			name:     "list with spaces",
			val:      "TLSv1.1, TLSv1.2 , TLSv1.3",
			expected: "TLS1_1",
		},
		{
			name:     "trailing comma",
			val:      "TLSv1.2,",
			expected: "TLS1_2",
		},
		{
			name:     "unrecognized version is skipped",
			val:      "TLSv1.2,TLSv1.4",
			expected: "TLS1_2",
		},
		{
			name:     "value with no recognized version is returned as is",
			val:      "TLSv1.4",
			expected: "TLSv1.4",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, minimumTLSVersion(tt.val))
		})
	}
}

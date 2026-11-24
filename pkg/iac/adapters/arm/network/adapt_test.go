package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure/arm/parser"
	"github.com/aquasecurity/trivy/pkg/iac/types"
)

func TestAdapt(t *testing.T) {
	tests := []struct {
		name     string
		source   string
		expected network.Network
	}{
		{
			name: "empty",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "nsg",
      "properties": {}
    },
	{
	  "type": "Microsoft.Network/networkSecurityGroups/securityRules",
	  "name": "nsg/rule",
	  "properties": {}
	},
	{
	  "type": "Microsoft.Network/networkWatchers/flowLogs",
	   "properties": {}
	}
  ]
}`,
			expected: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{{
					RetentionPolicy: network.RetentionPolicy{},
				}},
				SecurityGroups: []network.SecurityGroup{{
					Rules: []network.SecurityGroupRule{{}},
				}},
			},
		},
		{
			name: "complete",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Network/networkWatchers/flowLogs",
      "properties": {
        "retentionPolicy": {
          "days": 100,
          "enabled": true
        }
      }
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "nsg"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
      "name": "nsg/rule",
      "properties": {
        "access": "Allow",
        "direction": "Inbound",
        "protocol": "Tcp",
        "sourceAddressPrefix": "10.0.0.0/24",
        "sourceAddressPrefixes": [
          "10.0.1.0/24",
          "10.0.2.0/24"
        ],
        "sourcePortRange": "*",
        "sourcePortRanges": [
          "1000-2000",
          "3000"
        ],
        "destinationAddressPrefix": "172.16.0.0/16",
        "destinationAddressPrefixes": [
          "172.16.1.0/24",
          "172.16.2.0/24"
        ],
        "destinationPortRange": "80",
        "destinationPortRanges": [
          "8080",
          "443"
        ]
      }
    }
  ]
}`,
			expected: network.Network{
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{{
					RetentionPolicy: network.RetentionPolicy{
						Days:    types.IntTest(100),
						Enabled: types.BoolTest(true),
					},
				}},
				SecurityGroups: []network.SecurityGroup{{
					Rules: []network.SecurityGroupRule{{
						Allow:    types.BoolTest(true),
						Protocol: types.StringTest("Tcp"),
						SourceAddresses: []types.StringValue{
							types.StringTest("10.0.1.0/24"),
							types.StringTest("10.0.2.0/24"),
							types.StringTest("10.0.0.0/24"),
						},
						SourcePorts: []common.PortRange{
							{
								Start: types.IntTest(1000),
								End:   types.IntTest(2000),
							},
							{
								Start: types.IntTest(3000),
								End:   types.IntTest(3000),
							},
							{
								Start: types.IntTest(0),
								End:   types.IntTest(65535),
							},
						},
						DestinationAddresses: []types.StringValue{
							types.StringTest("172.16.1.0/24"),
							types.StringTest("172.16.2.0/24"),
							types.StringTest("172.16.0.0/16"),
						},
						DestinationPorts: []common.PortRange{
							{
								Start: types.IntTest(8080),
								End:   types.IntTest(8080),
							},
							{
								Start: types.IntTest(443),
								End:   types.IntTest(443),
							},
							{
								Start: types.IntTest(80),
								End:   types.IntTest(80),
							},
						},
					}},
				}},
			},
		},
		{
			name: "rules in the securityRules property",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "nsg",
      "properties": {
        "securityRules": [
          {"name": "ssh", "properties": {"access": "Allow", "protocol": "Tcp"}},
          {"name": "dns", "properties": {"access": "Deny", "protocol": "Udp"}}
        ]
      }
    }
  ]
}`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{{
					Rules: []network.SecurityGroupRule{
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Tcp")},
						{Protocol: types.StringTest("Udp")},
					},
				}},
			},
		},
		{
			name: "rules as child resources",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "nsg",
      "resources": [
        {
          "type": "securityRules",
          "name": "ssh",
          "properties": {"access": "Allow", "protocol": "Tcp"}
        },
        {
          "type": "Microsoft.Network/networkSecurityGroups/securityRules",
          "name": "dns",
          "properties": {"access": "Allow", "protocol": "Udp"}
        }
      ]
    }
  ]
}`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{{
					Rules: []network.SecurityGroupRule{
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Tcp")},
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Udp")},
					},
				}},
			},
		},
		{
			name: "top-level rules go to the group they name",
			source: `{
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "web"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "db"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
      "name": "web/https",
      "properties": {"access": "Allow", "protocol": "Tcp"}
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
      "name": "DB/sql",
      "properties": {"access": "Allow", "protocol": "Udp"}
    }
  ]
}`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{Rules: []network.SecurityGroupRule{
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Tcp")},
					}},
					{Rules: []network.SecurityGroupRule{
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Udp")},
					}},
				},
			},
		},
		{
			name: "top-level rule with an expression name goes to the orphan group",
			source: `{
  "parameters": {
    "nsgName": {"type": "string", "defaultValue": "web"}
  },
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "web"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "db"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
      "name": "[concat(parameters('nsgName'), '/https')]",
      "properties": {"access": "Allow", "protocol": "Tcp"}
    }
  ]
}`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{},
					{},
					{Rules: []network.SecurityGroupRule{
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Tcp")},
					}},
				},
			},
		},
		{
			name: "top-level rule goes to the orphan group when the group name is an expression",
			source: `{
  "parameters": {
    "nsgName": {"type": "string", "defaultValue": "web"}
  },
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups",
      "name": "[parameters('nsgName')]"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
      "name": "web/https",
      "properties": {"access": "Allow", "protocol": "Tcp"}
    }
  ]
}`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{},
					{Rules: []network.SecurityGroupRule{
						{Allow: types.BoolTest(true), Protocol: types.StringTest("Tcp")},
					}},
				},
			},
		},
		{
			name: "network interface with ip configurations",
			source: `{
			"resources": [
				{
					"type": "Microsoft.Network/networkInterfaces",
					"properties": {
						"enableIPForwarding": true,
						"ipConfigurations": [
							{
								"name": "primary-ip",
								"properties": {
									"primary": true,
									"subnet": {
										"id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet-primary"
									},
									"publicIPAddress": {
										"id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-primary"
									}
								}
							},
							{
								"name": "secondary-ip",
								"properties": {
									"primary": false,
									"subnet": {
										"id": "/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet-secondary"
									}
								}
							}
						]
					}
				}
			]
		}`,
			expected: network.Network{
				NetworkInterfaces: []network.NetworkInterface{
					{
						EnableIPForwarding: types.BoolTest(true),

						// backward compatibility — filled from primary config
						SubnetID:        types.StringTest("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet-primary"),
						HasPublicIP:     types.BoolTest(true),
						PublicIPAddress: types.StringTest("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-primary"),

						IPConfigurations: []network.IPConfiguration{
							{
								Primary: types.BoolTest(true),
								SubnetID: types.StringTest(
									"/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet-primary",
								),
								HasPublicIP:     types.BoolTest(true),
								PublicIPAddress: types.StringTest("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/publicIPAddresses/pip-primary"),
							},
							{
								Primary:         types.BoolTest(false),
								SubnetID:        types.StringTest("/subscriptions/abc/resourceGroups/rg/providers/Microsoft.Network/virtualNetworks/vnet/subnets/subnet-secondary"),
								HasPublicIP:     types.BoolTest(false),
								PublicIPAddress: types.StringTest(""),
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

func TestAdaptOrphanSecurityGroupIsUnmanaged(t *testing.T) {
	fsys := testutil.CreateFS(map[string]string{
		"test.json": `{
  "resources": [
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
      "name": "[format('{0}/ssh', parameters('nsgName'))]",
      "properties": {"access": "Allow", "protocol": "Tcp"}
    }
  ]
}`,
	})
	deployments, err := parser.New(fsys).ParseFS(t.Context(), ".")
	require.NoError(t, err)
	require.Len(t, deployments, 1)

	groups := Adapt(deployments[0]).SecurityGroups
	require.Len(t, groups, 1)
	assert.False(t, groups[0].Metadata.IsManaged())
	require.Len(t, groups[0].Rules, 1)
	assert.True(t, groups[0].Rules[0].Metadata.IsManaged())
}

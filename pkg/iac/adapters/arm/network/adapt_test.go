package network

import (
	"testing"

	"github.com/aquasecurity/trivy/pkg/iac/adapters/arm/adaptertest"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
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
      "properties": {}
    },
	{
	  "type": "Microsoft.Network/networkSecurityGroups/securityRules",
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
					RetentionPolicy: network.RetentionPolicy{
						Days:    types.IntTest(0),
						Enabled: types.BoolTest(false),
					},
				}},
				SecurityGroups: []network.SecurityGroup{{
					Rules: []network.SecurityGroupRule{{
						DestinationAddresses: []types.StringValue{types.StringTest("")},
						DestinationPorts:     []network.PortRange{{Start: types.IntTest(0), End: types.IntTest(65535)}},
						SourceAddresses:      []types.StringValue{types.StringTest("")},
						SourcePorts:          []network.PortRange{{Start: types.IntTest(0), End: types.IntTest(65535)}},
					}},
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
      "type": "Microsoft.Network/networkSecurityGroups"
    },
    {
      "type": "Microsoft.Network/networkSecurityGroups/securityRules",
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
						SourcePorts: []network.PortRange{
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
						DestinationPorts: []network.PortRange{
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
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adaptertest.AdaptAndCompare(t, tt.source, tt.expected, Adapt)
		})
	}
}

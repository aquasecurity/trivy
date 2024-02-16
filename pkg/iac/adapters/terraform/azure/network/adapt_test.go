package network

import (
	"testing"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  network.Network
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_network_security_rule" "example" {
				name                        = "example_security_rule"
				network_security_group_name = azurerm_network_security_group.example.name
				direction                   = "Inbound"
				access                      = "Allow"
				protocol                    = "TCP"
				source_port_range           = "*"
				destination_port_ranges     = ["3389"]
				source_address_prefix       = "4.53.160.75"
				destination_address_prefix  = "*"
		   }
		   
		   resource "azurerm_network_security_group" "example" {
			 name                = "tf-appsecuritygroup"
		   }

		   resource "azurerm_network_watcher_flow_log" "example" {
			resource_group_name  = azurerm_resource_group.example.name
			name                 = "example-log"
		  
			retention_policy {
			  enabled = true
			  days    = 7
			}		  
		  }
`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Outbound: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
								Allow:    iacTypes.Bool(true, iacTypes.NewTestMetadata()),
								SourceAddresses: []iacTypes.StringValue{
									iacTypes.String("4.53.160.75", iacTypes.NewTestMetadata()),
								},
								DestinationAddresses: []iacTypes.StringValue{
									iacTypes.String("*", iacTypes.NewTestMetadata()),
								},
								SourcePorts: []network.PortRange{
									{
										Metadata: iacTypes.NewTestMetadata(),
										Start:    0,
										End:      65535,
									},
								},
								DestinationPorts: []network.PortRange{
									{
										Metadata: iacTypes.NewTestMetadata(),
										Start:    3389,
										End:      3389,
									},
								},
								Protocol: iacTypes.String("TCP", iacTypes.NewTestMetadata()),
							},
						},
					},
				},
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Metadata: iacTypes.NewTestMetadata(),
						RetentionPolicy: network.RetentionPolicy{
							Metadata: iacTypes.NewTestMetadata(),
							Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
							Days:     iacTypes.Int(7, iacTypes.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
		   resource "azurerm_network_security_group" "example" {
			 name                = "tf-appsecuritygroup"
			 security_rule {
			 }
		   }
`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Metadata: iacTypes.NewTestMetadata(),
						Rules: []network.SecurityGroupRule{
							{
								Metadata: iacTypes.NewTestMetadata(),
								Outbound: iacTypes.Bool(false, iacTypes.NewTestMetadata()),
								Allow:    iacTypes.Bool(true, iacTypes.NewTestMetadata()),
								Protocol: iacTypes.String("", iacTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWatcherLog(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  network.NetworkWatcherFlowLog
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_network_watcher_flow_log" "watcher" {		
				retention_policy {
					enabled = true
					days = 90
				}
			}
`,
			expected: network.NetworkWatcherFlowLog{
				Metadata: iacTypes.NewTestMetadata(),
				RetentionPolicy: network.RetentionPolicy{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(true, iacTypes.NewTestMetadata()),
					Days:     iacTypes.Int(90, iacTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_network_watcher_flow_log" "watcher" {
				retention_policy {
				}
			}
`,
			expected: network.NetworkWatcherFlowLog{
				Metadata: iacTypes.NewTestMetadata(),
				RetentionPolicy: network.RetentionPolicy{
					Metadata: iacTypes.NewTestMetadata(),
					Enabled:  iacTypes.Bool(false, iacTypes.NewTestMetadata()),
					Days:     iacTypes.Int(0, iacTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWatcherLog(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_network_security_group" "example" {
		name                = "tf-appsecuritygroup"
	}
   
	resource "azurerm_network_security_rule" "example" {
		name                        = "example_security_rule"
		network_security_group_name = azurerm_network_security_group.example.name
		direction                   = "Inbound"
		access                      = "Allow"
		protocol                    = "TCP"
		source_port_range           = "*"
		destination_port_ranges     = ["3389"]
		source_address_prefix       = "4.53.160.75"
		destination_address_prefix  = "*"
   }
   
   resource "azurerm_network_watcher_flow_log" "example" {
	resource_group_name  = azurerm_resource_group.example.name
	name                 = "example-log"
  
	retention_policy {
	  enabled = true
	  days    = 7
	}		  
  	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.SecurityGroups, 1)
	require.Len(t, adapted.NetworkWatcherFlowLogs, 1)

	securityGroup := adapted.SecurityGroups[0]
	rule := securityGroup.Rules[0]
	watcher := adapted.NetworkWatcherFlowLogs[0]

	assert.Equal(t, 2, securityGroup.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, securityGroup.Metadata.Range().GetEndLine())

	assert.Equal(t, 6, rule.Metadata.Range().GetStartLine())
	assert.Equal(t, 16, rule.Metadata.Range().GetEndLine())

	assert.Equal(t, 9, rule.Outbound.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, rule.Outbound.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, rule.Allow.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, rule.Allow.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, rule.Protocol.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, rule.Protocol.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, rule.SourcePorts[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 12, rule.SourcePorts[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 13, rule.DestinationPorts[0].Metadata.Range().GetStartLine())
	assert.Equal(t, 13, rule.DestinationPorts[0].Metadata.Range().GetEndLine())

	assert.Equal(t, 14, rule.SourceAddresses[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, rule.SourceAddresses[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, rule.DestinationAddresses[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, rule.DestinationAddresses[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, watcher.Metadata.Range().GetStartLine())
	assert.Equal(t, 26, watcher.Metadata.Range().GetEndLine())

	assert.Equal(t, 22, watcher.RetentionPolicy.Metadata.Range().GetStartLine())
	assert.Equal(t, 25, watcher.RetentionPolicy.Metadata.Range().GetEndLine())

	assert.Equal(t, 23, watcher.RetentionPolicy.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, watcher.RetentionPolicy.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, watcher.RetentionPolicy.Days.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, watcher.RetentionPolicy.Days.GetMetadata().Range().GetEndLine())
}

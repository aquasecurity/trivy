package network

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
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
			enabled              = true
		  
			retention_policy {
			  enabled = true
			  days    = 7
			}		  
		  }
`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Rules: []network.SecurityGroupRule{
							{
								Allow: iacTypes.BoolTest(true),
								SourceAddresses: []iacTypes.StringValue{
									iacTypes.StringTest("4.53.160.75"),
								},
								DestinationAddresses: []iacTypes.StringValue{
									iacTypes.StringTest("*"),
								},
								SourcePorts: []common.PortRange{
									{
										End: iacTypes.IntTest(65535),
									},
								},
								DestinationPorts: []common.PortRange{
									{
										Start: iacTypes.IntTest(3389),
										End:   iacTypes.IntTest(3389),
									},
								},
								Protocol: iacTypes.StringTest("TCP"),
							},
						},
					},
				},
				NetworkWatcherFlowLogs: []network.NetworkWatcherFlowLog{
					{
						Enabled: iacTypes.BoolTest(true),
						RetentionPolicy: network.RetentionPolicy{
							Enabled: iacTypes.BoolTest(true),
							Days:    iacTypes.IntTest(7),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `resource "azurerm_network_security_group" "example" {
	name = "tf-appsecuritygroup"
	security_rule {}
}
`,
			expected: network.Network{
				SecurityGroups: []network.SecurityGroup{
					{
						Rules: []network.SecurityGroupRule{
							{
								Allow: iacTypes.BoolTest(true),
							},
						},
					},
				},
			},
		},
		{
			name: "network interface",
			terraform: `resource "azurerm_network_interface" "example" {
	name                = "example-nic"
	location            = "eastus"
	resource_group_name = "example-rg"

	ip_configuration {
		name = "primary-ip"
		primary = true
		subnet_id = "subnet-primary-id"
		public_ip_address_id = "public-ip-primary-id"
	}

	ip_configuration {
		name = "secondary-ip"
		subnet_id = "subnet-secondary-id"
	}
}
`,
			expected: network.Network{
				NetworkInterfaces: []network.NetworkInterface{
					{
						// legacy fields filled from primary
						SubnetID:        iacTypes.StringTest("subnet-primary-id"),
						HasPublicIP:     iacTypes.BoolTest(true),
						PublicIPAddress: iacTypes.StringTest("public-ip-primary-id"),

						IPConfigurations: []network.IPConfiguration{
							{
								SubnetID:        iacTypes.StringTest("subnet-primary-id"),
								Primary:         iacTypes.BoolTest(true),
								HasPublicIP:     iacTypes.BoolTest(true),
								PublicIPAddress: iacTypes.StringTest("public-ip-primary-id"),
							},
							{
								SubnetID: iacTypes.StringTest("subnet-secondary-id"),
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
				enabled = true
				retention_policy {
					enabled = true
					days = 90
				}
			}
`,
			expected: network.NetworkWatcherFlowLog{
				Enabled: iacTypes.BoolTest(true),
				RetentionPolicy: network.RetentionPolicy{
					Enabled: iacTypes.BoolTest(true),
					Days:    iacTypes.IntTest(90),
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
				RetentionPolicy: network.RetentionPolicy{},
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

func Test_AdaptNetworkInterface_AssociationSecurityGroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  int
	}{
		{
			name: "security group via association resource",
			terraform: `
resource "azurerm_network_security_group" "example" {
	name = "example-nsg"
}

resource "azurerm_network_interface" "example" {
	name                = "example-nic"
	location            = "eastus"
	resource_group_name = "example-rg"

	ip_configuration {
		name                          = "primary"
		subnet_id                     = "subnet-primary-id"
		private_ip_address_allocation = "Dynamic"
	}
}

resource "azurerm_network_interface_security_group_association" "example" {
	network_interface_id      = azurerm_network_interface.example.id
	network_security_group_id = azurerm_network_security_group.example.id
}
`,
			expected: 1,
		},
		{
			name: "security group deduplicated when legacy and association both set",
			terraform: `
resource "azurerm_network_security_group" "example" {
	name = "example-nsg"
}

resource "azurerm_network_interface" "example" {
	name                      = "example-nic"
	location                  = "eastus"
	resource_group_name       = "example-rg"
	network_security_group_id = azurerm_network_security_group.example.id

	ip_configuration {
		name                          = "primary"
		subnet_id                     = "subnet-primary-id"
		private_ip_address_allocation = "Dynamic"
	}
}

resource "azurerm_network_interface_security_group_association" "example" {
	network_interface_id      = azurerm_network_interface.example.id
	network_security_group_id = azurerm_network_security_group.example.id
}
`,
			expected: 1,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			nics := modules.GetResourcesByType("azurerm_network_interface")
			require.Len(t, nics, 1)

			adapted := AdaptNetworkInterface(nics[0], modules)
			require.Len(t, adapted.SecurityGroups, test.expected)
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

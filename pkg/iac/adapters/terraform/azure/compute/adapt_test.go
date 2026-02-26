package compute

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/trivy/internal/testutil"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/common"
	"github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/tftestutil"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Test_adaptManagedDisk(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  compute.ManagedDisk
	}{
		{
			name: "encryption explicitly disabled",
			terraform: `
resource "azurerm_managed_disk" "example" {
	encryption_settings {
		enabled = false
	}
}`,
			expected: compute.ManagedDisk{
				Encryption: compute.Encryption{},
			},
		},
		{
			name: "encryption enabled by default",
			terraform: `
resource "azurerm_managed_disk" "example" {
}`,
			expected: compute.ManagedDisk{
				Encryption: compute.Encryption{
					Enabled: iacTypes.BoolTest(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptManagedDisk(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptLinuxVM(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  compute.LinuxVirtualMachine
	}{
		{
			name: "no custom data",
			terraform: `
resource "azurerm_virtual_machine" "example" {
	name                            = "linux-machine"
	resource_group_name             = azurerm_resource_group.example.name
	location                        = azurerm_resource_group.example.location
	size                            = "Standard_F2"
	admin_username                  = "adminuser"

	os_profile_linux_config {
		ssh_keys = [{
			key_data = file("~/.ssh/id_rsa.pub")
			path = "~/.ssh/id_rsa.pub"
		}]
		disable_password_authentication = true
	}
}
`,
			expected: compute.LinuxVirtualMachine{
				VirtualMachine: compute.VirtualMachine{},
				OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
					DisablePasswordAuthentication: iacTypes.BoolTest(true),
				},
			},
		},
		{
			name: "custom data",
			terraform: `
resource "azurerm_virtual_machine" "example" {
	name = "example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
		EOF
	}
}`,
			expected: compute.LinuxVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					CustomData: iacTypes.StringTest(
						"export DATABASE_PASSWORD=\\\"SomeSortOfPassword\\\"\n"),
				},
				OSProfileLinuxConfig: compute.OSProfileLinuxConfig{},
			},
		},
		{
			name: "with network interface",
			terraform: `
resource "azurerm_resource_group" "example" {
  name     = "example-resources"
  location = "West Europe"
}

resource "azurerm_linux_virtual_machine" "example" {
	name                  = "example-vm"
	resource_group_name   = "example-resources"
	location              = "East US"
	size                  = "Standard_F2"
	network_interface_ids = [
		azurerm_network_interface.example.id,
	]
	admin_username = "adminuser"
	
	os_disk {
		caching              = "ReadWrite"
		storage_account_type = "Standard_LRS"
	}
}

resource "azurerm_network_interface" "example" {
  name                = "example-nic"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  ip_configuration {
    name                 = "internal"
		public_ip_address_id = "test-public-ip-id"
  }

	network_security_group_id = azurerm_network_security_group.example.id
}

resource "azurerm_network_security_group" "example" {
  name                = "example-nsg"
  location            = azurerm_resource_group.example.location
  resource_group_name = azurerm_resource_group.example.name

  security_rule {
    name                       = "test123"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}
`,
			expected: compute.LinuxVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					NetworkInterfaces: []network.NetworkInterface{
						{
							HasPublicIP:     iacTypes.BoolTest(true),
							PublicIPAddress: iacTypes.StringTest("test-public-ip-id"),
							IPConfigurations: []network.IPConfiguration{
								{
									HasPublicIP:     iacTypes.BoolTest(true),
									PublicIPAddress: iacTypes.StringTest("test-public-ip-id"),
								},
							},
							SecurityGroups: []network.SecurityGroup{
								{
									Rules: []network.SecurityGroupRule{
										{
											Allow:                iacTypes.BoolTest(true),
											Protocol:             iacTypes.StringTest("Tcp"),
											DestinationAddresses: []iacTypes.StringValue{iacTypes.StringTest("*")},
											DestinationPorts:     []common.PortRange{common.FullPortRange(iacTypes.NewTestMetadata())},
											SourceAddresses:      []iacTypes.StringValue{iacTypes.StringTest("*")},
											SourcePorts:          []common.PortRange{common.FullPortRange(iacTypes.NewTestMetadata())},
										},
									},
								},
							},
						},
					},
				},
				OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
					DisablePasswordAuthentication: iacTypes.BoolTest(true),
				},
			},
		},
		{
			name: "without network interfaces",
			terraform: `
resource "azurerm_linux_virtual_machine" "example" {
	name                  = "example-vm"
	resource_group_name   = "example-resources"
	location              = "East US"
	size                  = "Standard_F2"
	network_interface_ids = []
	admin_username = "adminuser"
	
	os_disk {
		caching              = "ReadWrite"
		storage_account_type = "Standard_LRS"
	}
}`,
			expected: compute.LinuxVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					// Empty array in Terraform is parsed as nil
				},
				OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
					DisablePasswordAuthentication: iacTypes.BoolTest(true),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLinuxVM(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWindowsVM(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  compute.WindowsVirtualMachine
	}{
		{
			name: "old resource",
			terraform: `
resource "azurerm_virtual_machine" "example" {
	name = "example"
	os_profile_windows_config {
	}
	os_profile {
		custom_data =<<EOF
export DATABASE_PASSWORD=\"SomeSortOfPassword\"
			EOF
	}
}`,
			expected: compute.WindowsVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					CustomData: iacTypes.StringTest("export DATABASE_PASSWORD=\\\"SomeSortOfPassword\\\"\n"),
				},
			},
		},
		{
			name: "new resource",
			terraform: `
resource "azurerm_windows_virtual_machine" "example" {
	name                = "example-machine"
	custom_data =<<EOF
export GREETING="Hello there"
	EOF
	}`,
			expected: compute.WindowsVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					CustomData: iacTypes.StringTest("export GREETING=\"Hello there\"\n"),
				},
			},
		},
		{
			name: "with network interfaces",
			terraform: `
resource "azurerm_windows_virtual_machine" "example" {
	name                  = "example-machine"
	resource_group_name   = "example-resources"
	location              = "East US"
	size                  = "Standard_F2"
	network_interface_ids = ["nic-1", "nic-2"]
	admin_username        = "adminuser"
	admin_password        = "P@ssw0rd1234!"
	
	os_disk {
		caching              = "ReadWrite"
		storage_account_type = "Standard_LRS"
	}
}`,
			expected: compute.WindowsVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					NetworkInterfaces: []network.NetworkInterface{
						{},
						{},
					},
				},
			},
		},
		{
			name: "with network interface security group association",
			terraform: `
resource "azurerm_windows_virtual_machine" "example" {
	name                  = "example-machine"
	resource_group_name   = "example-resources"
	location              = "East US"
	size                  = "Standard_F2"
	network_interface_ids = [
		azurerm_network_interface.example.id,
	]
	admin_username = "adminuser"
	admin_password = "P@ssw0rd1234!"

	os_disk {
		caching              = "ReadWrite"
		storage_account_type = "Standard_LRS"
	}
}

resource "azurerm_network_interface" "example" {
  name                = "example-nic"
  location            = "eastus"
  resource_group_name = "example-rg"

  ip_configuration {
    name                 = "internal"
    public_ip_address_id = "test-public-ip-id"
  }
}

resource "azurerm_network_security_group" "example" {
  name                = "example-nsg"
  location            = "eastus"
  resource_group_name = "example-rg"

  security_rule {
    name                       = "test123"
    priority                   = 100
    direction                  = "Inbound"
    access                     = "Allow"
    protocol                   = "Tcp"
    source_port_range          = "*"
    destination_port_range     = "*"
    source_address_prefix      = "*"
    destination_address_prefix = "*"
  }
}

resource "azurerm_network_interface_security_group_association" "example" {
	network_interface_id      = azurerm_network_interface.example.id
	network_security_group_id = azurerm_network_security_group.example.id
}
`,
			expected: compute.WindowsVirtualMachine{
				VirtualMachine: compute.VirtualMachine{
					NetworkInterfaces: []network.NetworkInterface{
						{
							HasPublicIP:     iacTypes.BoolTest(true),
							PublicIPAddress: iacTypes.StringTest("test-public-ip-id"),
							IPConfigurations: []network.IPConfiguration{
								{
									HasPublicIP:     iacTypes.BoolTest(true),
									PublicIPAddress: iacTypes.StringTest("test-public-ip-id"),
								},
							},
							SecurityGroups: []network.SecurityGroup{
								{
									Rules: []network.SecurityGroupRule{
										{
											Allow:                iacTypes.BoolTest(true),
											Protocol:             iacTypes.StringTest("Tcp"),
											DestinationAddresses: []iacTypes.StringValue{iacTypes.StringTest("*")},
											DestinationPorts:     []common.PortRange{common.FullPortRange(iacTypes.NewTestMetadata())},
											SourceAddresses:      []iacTypes.StringValue{iacTypes.StringTest("*")},
											SourcePorts:          []common.PortRange{common.FullPortRange(iacTypes.NewTestMetadata())},
										},
									},
								},
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
			resources := modules.GetResourcesByType("azurerm_windows_virtual_machine", AzureVirtualMachine)
			require.NotEmpty(t, resources)
			adapted := adaptWindowsVM(resources[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
resource "azurerm_managed_disk" "good_example" {
	encryption_settings {
		enabled = false
	}
}

resource "azurerm_virtual_machine" "example" {
	name                            = "linux-machine"

	os_profile_linux_config {
		ssh_keys = [{
			key_data = file("~/.ssh/id_rsa.pub")
			path = "~/.ssh/id_rsa.pub"
		}]
		disable_password_authentication = true
	}
	os_profile {
		custom_data =<<EOF
		export DATABASE_PASSWORD=\"SomeSortOfPassword\"
		EOF
	}
}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.ManagedDisks, 1)
	require.Len(t, adapted.LinuxVirtualMachines, 1)

	managedDisk := adapted.ManagedDisks[0]
	linuxVM := adapted.LinuxVirtualMachines[0]

	assert.Equal(t, 4, managedDisk.Encryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, managedDisk.Encryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, linuxVM.OSProfileLinuxConfig.DisablePasswordAuthentication.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, linuxVM.OSProfileLinuxConfig.DisablePasswordAuthentication.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, linuxVM.VirtualMachine.CustomData.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, linuxVM.VirtualMachine.CustomData.GetMetadata().Range().GetEndLine())
}

package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/compute"

	"github.com/aquasecurity/trivy/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/trivy/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
				Metadata: defsecTypes.NewTestMetadata(),
				Encryption: compute.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "encryption enabled by default",
			terraform: `
resource "azurerm_managed_disk" "example" {
}`,
			expected: compute.ManagedDisk{
				Metadata: defsecTypes.NewTestMetadata(),
				Encryption: compute.Encryption{
					Metadata: defsecTypes.NewTestMetadata(),
					Enabled:  defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				VirtualMachine: compute.VirtualMachine{
					Metadata:   defsecTypes.NewTestMetadata(),
					CustomData: defsecTypes.String("", defsecTypes.NewTestMetadata()),
				},
				OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
					Metadata:                      defsecTypes.NewTestMetadata(),
					DisablePasswordAuthentication: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				VirtualMachine: compute.VirtualMachine{
					Metadata: defsecTypes.NewTestMetadata(),
					CustomData: defsecTypes.String(
						`export DATABASE_PASSWORD=\"SomeSortOfPassword\"
`, defsecTypes.NewTestMetadata()),
				},
				OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
					Metadata:                      defsecTypes.NewTestMetadata(),
					DisablePasswordAuthentication: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptLinuxVM(modules.GetBlocks()[0])
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
				Metadata: defsecTypes.NewTestMetadata(),
				VirtualMachine: compute.VirtualMachine{
					Metadata: defsecTypes.NewTestMetadata(),
					CustomData: defsecTypes.String(`export DATABASE_PASSWORD=\"SomeSortOfPassword\"
`, defsecTypes.NewTestMetadata()),
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
				Metadata: defsecTypes.NewTestMetadata(),
				VirtualMachine: compute.VirtualMachine{
					Metadata: defsecTypes.NewTestMetadata(),
					CustomData: defsecTypes.String(`export GREETING="Hello there"
`, defsecTypes.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWindowsVM(modules.GetBlocks()[0])
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

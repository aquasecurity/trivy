package compute

import (
	"encoding/base64"

	anetwork "github.com/aquasecurity/trivy/pkg/iac/adapters/terraform/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/terraform"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

const AzureVirtualMachine = "azurerm_virtual_machine"

func Adapt(modules terraform.Modules) compute.Compute {
	return adaptCompute(modules)
}

func adaptCompute(modules terraform.Modules) compute.Compute {

	var managedDisks []compute.ManagedDisk
	var linuxVirtualMachines []compute.LinuxVirtualMachine
	var windowsVirtualMachines []compute.WindowsVirtualMachine

	for _, module := range modules {

		for _, resource := range module.GetResourcesByType("azurerm_linux_virtual_machine") {
			linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource, modules))
		}
		for _, resource := range module.GetResourcesByType("azurerm_windows_virtual_machine") {
			windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource, modules))
		}
		for _, resource := range module.GetResourcesByType(AzureVirtualMachine) {
			if linuxConfigBlock := resource.GetBlock("os_profile_linux_config"); linuxConfigBlock.IsNotNil() {
				linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource, modules))
			} else if windowsConfigBlock := resource.GetBlock("os_profile_windows_config"); windowsConfigBlock.IsNotNil() {
				windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource, modules))
			}
		}
		for _, resource := range module.GetResourcesByType("azurerm_managed_disk") {
			managedDisks = append(managedDisks, adaptManagedDisk(resource))
		}
	}

	return compute.Compute{
		LinuxVirtualMachines:   linuxVirtualMachines,
		WindowsVirtualMachines: windowsVirtualMachines,
		ManagedDisks:           managedDisks,
	}
}

func adaptManagedDisk(resource *terraform.Block) compute.ManagedDisk {

	disk := compute.ManagedDisk{
		Metadata: resource.GetMetadata(),
		Encryption: compute.Encryption{
			Metadata: resource.GetMetadata(),
			// encryption is enabled by default - https://github.com/hashicorp/terraform-provider-azurerm/blob/baf55926fe813011003ee4fb0e8e6134fcfcca87/internal/services/compute/managed_disk_resource.go#L288
			Enabled: iacTypes.BoolDefault(true, resource.GetMetadata()),
		},
	}

	encryptionBlock := resource.GetBlock("encryption_settings")
	if encryptionBlock.IsNotNil() {
		disk.Encryption.Metadata = encryptionBlock.GetMetadata()
		enabledAttr := encryptionBlock.GetAttribute("enabled")
		disk.Encryption.Enabled = enabledAttr.AsBoolValueOrDefault(true, encryptionBlock)
	}

	return disk
}

func adaptLinuxVM(resource *terraform.Block, modules terraform.Modules) compute.LinuxVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == AzureVirtualMachine {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}
	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := iacTypes.StringDefault("", workingBlock.GetMetadata())
	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = iacTypes.String(string(encoded), customDataAttr.GetMetadata())
	}

	networkInterfaces := resolveNetworkInterfaces(resource, modules)

	if resource.TypeLabel() == AzureVirtualMachine {
		workingBlock = resource.GetBlock("os_profile_linux_config")
	}
	disablePasswordAuthAttr := workingBlock.GetAttribute("disable_password_authentication")
	disablePasswordAuthVal := disablePasswordAuthAttr.AsBoolValueOrDefault(true, workingBlock)

	return compute.LinuxVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute.VirtualMachine{
			Metadata:          resource.GetMetadata(),
			CustomData:        customDataVal,
			NetworkInterfaces: networkInterfaces,
		},
		OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
			Metadata:                      resource.GetMetadata(),
			DisablePasswordAuthentication: disablePasswordAuthVal,
		},
	}
}

func adaptWindowsVM(resource *terraform.Block, modules terraform.Modules) compute.WindowsVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == AzureVirtualMachine {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}

	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := iacTypes.StringDefault("", workingBlock.GetMetadata())

	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = iacTypes.String(string(encoded), customDataAttr.GetMetadata())
	}

	networkInterfaces := resolveNetworkInterfaces(resource, modules)

	return compute.WindowsVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute.VirtualMachine{
			Metadata:          resource.GetMetadata(),
			CustomData:        customDataVal,
			NetworkInterfaces: networkInterfaces,
		},
	}
}

func resolveNetworkInterfaces(resource *terraform.Block, modules terraform.Modules) []network.NetworkInterface {
	nicIDsAttr := resource.GetAttribute("network_interface_ids")
	if nicIDsAttr.IsNil() {
		return nil
	}

	var networkInterfaces []network.NetworkInterface
	for _, nicIDVal := range nicIDsAttr.AsStringValues() {
		if referencedNIC, err := modules.GetReferencedBlock(nicIDsAttr, resource); err == nil {
			ni := anetwork.AdaptNetworkInterface(referencedNIC, modules)
			networkInterfaces = append(networkInterfaces, ni)
			continue
		}

		networkInterfaces = append(networkInterfaces, network.NetworkInterface{
			Metadata:           iacTypes.NewUnmanagedMetadata(),
			EnableIPForwarding: iacTypes.BoolDefault(false, nicIDVal.GetMetadata()),
			SubnetID:           iacTypes.StringDefault("", nicIDVal.GetMetadata()),
			HasPublicIP:        iacTypes.BoolDefault(false, nicIDVal.GetMetadata()),
			PublicIPAddress:    iacTypes.StringDefault("", nicIDVal.GetMetadata()),
		})
	}

	return networkInterfaces
}

package compute

import (
	"encoding/base64"

	"github.com/aquasecurity/defsec/parsers/terraform"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/compute"
)

func Adapt(modules terraform.Modules) compute.Compute {
	return adaptCompute(modules)
}

func adaptCompute(modules terraform.Modules) compute.Compute {

	var managedDisks []compute.ManagedDisk
	var linuxVirtualMachines []compute.LinuxVirtualMachine
	var windowsVirtualMachines []compute.WindowsVirtualMachine

	for _, module := range modules {

		for _, resource := range module.GetResourcesByType("azurerm_linux_virtual_machine") {
			linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_windows_virtual_machine") {
			windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_virtual_machine") {
			if resource.HasChild("os_profile_linux_config") {
				linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
			} else if resource.HasChild("os_profile_windows_config") {
				windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
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
	encryptionBlock := resource.GetBlock("encryption_settings")
	// encryption is enabled by default - https://github.com/hashicorp/terraform-provider-azurerm/blob/baf55926fe813011003ee4fb0e8e6134fcfcca87/internal/services/compute/managed_disk_resource.go#L288
	enabledVal := types.BoolDefault(true, resource.GetMetadata())

	if encryptionBlock.IsNotNil() {
		enabledAttr := encryptionBlock.GetAttribute("enabled")
		enabledVal = enabledAttr.AsBoolValueOrDefault(false, encryptionBlock)
	}

	return compute.ManagedDisk{
		Metadata: resource.GetMetadata(),
		Encryption: compute.Encryption{
			Enabled: enabledVal,
		},
	}
}

func adaptLinuxVM(resource *terraform.Block) compute.LinuxVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}
	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := types.StringDefault("", workingBlock.GetMetadata())
	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = types.String(string(encoded), workingBlock.GetMetadata())
	}

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		workingBlock = resource.GetBlock("os_profile_linux_config")
	}
	disablePasswordAuthAttr := workingBlock.GetAttribute("disable_password_authentication")
	disablePasswordAuthVal := disablePasswordAuthAttr.AsBoolValueOrDefault(true, workingBlock)

	return compute.LinuxVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute.VirtualMachine{
			CustomData: customDataVal,
		},
		OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
			DisablePasswordAuthentication: disablePasswordAuthVal,
		},
	}
}

func adaptWindowsVM(resource *terraform.Block) compute.WindowsVirtualMachine {
	workingBlock := resource

	if resource.TypeLabel() == "azurerm_virtual_machine" {
		if b := resource.GetBlock("os_profile"); b.IsNotNil() {
			workingBlock = b
		}
	}

	customDataAttr := workingBlock.GetAttribute("custom_data")
	customDataVal := types.StringDefault("", workingBlock.GetMetadata())

	if customDataAttr.IsResolvable() && customDataAttr.IsString() {
		encoded, err := base64.StdEncoding.DecodeString(customDataAttr.Value().AsString())
		if err != nil {
			encoded = []byte(customDataAttr.Value().AsString())
		}
		customDataVal = types.String(string(encoded), workingBlock.GetMetadata())
	}

	return compute.WindowsVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute.VirtualMachine{
			CustomData: customDataVal,
		},
	}
}

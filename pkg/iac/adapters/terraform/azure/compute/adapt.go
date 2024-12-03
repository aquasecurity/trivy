package compute

import (
	"encoding/base64"

	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
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
			linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVM(resource))
		}
		for _, resource := range module.GetResourcesByType("azurerm_windows_virtual_machine") {
			windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVM(resource))
		}
		for _, resource := range module.GetResourcesByType(AzureVirtualMachine) {
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

func adaptLinuxVM(resource *terraform.Block) compute.LinuxVirtualMachine {
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

	if resource.TypeLabel() == AzureVirtualMachine {
		workingBlock = resource.GetBlock("os_profile_linux_config")
	}
	disablePasswordAuthAttr := workingBlock.GetAttribute("disable_password_authentication")
	disablePasswordAuthVal := disablePasswordAuthAttr.AsBoolValueOrDefault(true, workingBlock)

	return compute.LinuxVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute.VirtualMachine{
			Metadata:   resource.GetMetadata(),
			CustomData: customDataVal,
		},
		OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
			Metadata:                      resource.GetMetadata(),
			DisablePasswordAuthentication: disablePasswordAuthVal,
		},
	}
}

func adaptWindowsVM(resource *terraform.Block) compute.WindowsVirtualMachine {
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

	return compute.WindowsVirtualMachine{
		Metadata: resource.GetMetadata(),
		VirtualMachine: compute.VirtualMachine{
			Metadata:   resource.GetMetadata(),
			CustomData: customDataVal,
		},
	}
}

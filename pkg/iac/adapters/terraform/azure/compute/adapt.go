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

func resolveNetworkInterfaces(resource *terraform.Block, modules terraform.Modules) []compute.NetworkInterface {
	var networkInterfaces []compute.NetworkInterface

	nicIDsAttr := resource.GetAttribute("network_interface_ids")
	if nicIDsAttr.IsNil() {
		return networkInterfaces
	}

	for _, nicIDVal := range nicIDsAttr.AsStringValues() {
		if referencedNIC, err := modules.GetReferencedBlock(nicIDsAttr, resource); err == nil {
			ni := adaptNetworkInterface(referencedNIC, modules)
			networkInterfaces = append(networkInterfaces, ni)
			continue
		}

		networkInterfaces = append(networkInterfaces, compute.NetworkInterface{
			Metadata:        iacTypes.NewUnmanagedMetadata(),
			SubnetID:        iacTypes.StringDefault("", nicIDVal.GetMetadata()),
			SecurityGroups:  nil,
			HasPublicIP:     iacTypes.BoolDefault(false, nicIDVal.GetMetadata()),
			PublicIPAddress: iacTypes.StringDefault("", nicIDVal.GetMetadata()),
		})
	}

	return networkInterfaces
}

func adaptNetworkInterface(resource *terraform.Block, modules terraform.Modules) compute.NetworkInterface {
	ni := compute.NetworkInterface{
		Metadata:        resource.GetMetadata(),
		SubnetID:        iacTypes.StringDefault("", resource.GetMetadata()),
		SecurityGroups:  nil,
		HasPublicIP:     iacTypes.BoolDefault(false, resource.GetMetadata()),
		PublicIPAddress: iacTypes.StringDefault("", resource.GetMetadata()),
	}

	if nsgAttr := resource.GetAttribute("network_security_group_id"); nsgAttr.IsNotNil() {
		if referencedNSG, err := modules.GetReferencedBlock(nsgAttr, resource); err == nil {
			ni.SecurityGroups = []network.SecurityGroup{adaptSecurityGroupFromBlock(referencedNSG)}
		}
	}

	ipConfigs := resource.GetBlocks("ip_configuration")
	if len(ipConfigs) > 0 {
		ipConfig := ipConfigs[0]
		if subnetAttr := ipConfig.GetAttribute("subnet_id"); subnetAttr.IsNotNil() {
			ni.SubnetID = subnetAttr.AsStringValueOrDefault("", ipConfig)
		}

		if publicIPAttr := ipConfig.GetAttribute("public_ip_address_id"); publicIPAttr.IsNotNil() {
			ni.HasPublicIP = iacTypes.Bool(true, publicIPAttr.GetMetadata())
		}
	}

	return ni
}

func adaptSecurityGroupFromBlock(resource *terraform.Block) network.SecurityGroup {
	var rules []network.SecurityGroupRule
	for _, ruleBlock := range resource.GetBlocks("security_rule") {
		rules = append(rules, anetwork.AdaptSGRule(ruleBlock))
	}
	return network.SecurityGroup{
		Metadata: resource.GetMetadata(),
		Rules:    rules,
	}
}

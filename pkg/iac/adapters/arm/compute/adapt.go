package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	"github.com/aquasecurity/trivy/pkg/iac/scanners/azure"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

func Adapt(deployment azure.Deployment) compute.Compute {
	return compute.Compute{
		LinuxVirtualMachines:   adaptLinuxVirtualMachines(deployment),
		WindowsVirtualMachines: adaptWindowsVirtualMachines(deployment),
		ManagedDisks:           adaptManagedDisks(deployment),
	}
}

func adaptManagedDisks(deployment azure.Deployment) []compute.ManagedDisk {
	var managedDisks []compute.ManagedDisk

	for _, resource := range deployment.GetResourcesByType("Microsoft.Compute/disks") {
		managedDisks = append(managedDisks, adaptManagedDisk(resource))
	}

	return managedDisks
}

func adaptManagedDisk(resource azure.Resource) compute.ManagedDisk {
	hasEncryption := resource.Properties.HasKey("encryption")

	return compute.ManagedDisk{
		Metadata: resource.Metadata,
		Encryption: compute.Encryption{
			Metadata: resource.Metadata,
			Enabled:  iacTypes.Bool(hasEncryption, resource.Metadata),
		},
	}
}

func adaptWindowsVirtualMachines(deployment azure.Deployment) (windowsVirtualMachines []compute.WindowsVirtualMachine) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Compute/virtualMachines") {
		if resource.Properties.GetMapValue("osProfile").GetMapValue("windowsConfiguration").AsMap() != nil {
			windowsVirtualMachines = append(windowsVirtualMachines, adaptWindowsVirtualMachine(resource))
		}
	}

	return windowsVirtualMachines
}

func adaptWindowsVirtualMachine(resource azure.Resource) compute.WindowsVirtualMachine {
	networkProfile := resource.Properties.GetMapValue("networkProfile")
	networkInterfaces := extractNetworkInterfaces(networkProfile, resource.Metadata)

	return compute.WindowsVirtualMachine{
		Metadata: resource.Metadata,
		VirtualMachine: compute.VirtualMachine{
			Metadata: resource.Metadata,
			CustomData: resource.Properties.GetMapValue("osProfile").
				GetMapValue("customData").AsStringValue("", resource.Metadata),
			NetworkInterfaces: networkInterfaces,
		},
	}
}

func adaptLinuxVirtualMachines(deployment azure.Deployment) (linuxVirtualMachines []compute.LinuxVirtualMachine) {
	for _, resource := range deployment.GetResourcesByType("Microsoft.Compute/virtualMachines") {
		if resource.Properties.GetMapValue("osProfile").GetMapValue("linuxConfiguration").AsMap() != nil {
			linuxVirtualMachines = append(linuxVirtualMachines, adaptLinuxVirtualMachine(resource))
		}
	}

	return linuxVirtualMachines
}

func adaptLinuxVirtualMachine(resource azure.Resource) compute.LinuxVirtualMachine {
	networkProfile := resource.Properties.GetMapValue("networkProfile")
	networkInterfaces := extractNetworkInterfaces(networkProfile, resource.Metadata)

	return compute.LinuxVirtualMachine{
		Metadata: resource.Metadata,
		VirtualMachine: compute.VirtualMachine{
			Metadata: resource.Metadata,
			CustomData: resource.Properties.GetMapValue("osProfile").
				GetMapValue("customData").AsStringValue("", resource.Metadata),
			NetworkInterfaces: networkInterfaces,
		},
		OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
			Metadata: resource.Metadata,
			DisablePasswordAuthentication: resource.Properties.GetMapValue("osProfile").
				GetMapValue("linuxConfiguration").
				GetMapValue("disablePasswordAuthentication").AsBoolValue(false, resource.Metadata),
		},
	}

}

func extractNetworkInterfaces(networkProfile azure.Value, metadata iacTypes.Metadata) []network.NetworkInterface {
	var networkInterfaces []network.NetworkInterface

	nicsArray := networkProfile.GetMapValue("networkInterfaces").AsList()
	for _, nic := range nicsArray {
		nicID := nic.GetMapValue("id").AsStringValue("", metadata)
		if nicID.Value() != "" {
			// Create a minimal NetworkInterface object with the ID information
			// In ARM templates, we don't have direct access to subnet details like in Terraform
			// EnableIPForwarding is not available from the VM's networkProfile, so it defaults to false
			// Since we only have a reference to the network interface (not the full resource),
			// we mark it as unmanaged so that Rego policies can skip it using isManaged() checks
			unmanagedMetadata := iacTypes.NewUnmanagedMetadata()
			networkInterface := network.NetworkInterface{
				Metadata:           unmanagedMetadata,
				EnableIPForwarding: iacTypes.BoolDefault(false, unmanagedMetadata),
				SubnetID:           iacTypes.StringDefault("", unmanagedMetadata),
				SecurityGroups:     nil,
				HasPublicIP:        iacTypes.BoolDefault(false, unmanagedMetadata),
				PublicIPAddress:    iacTypes.StringDefault("", unmanagedMetadata),
			}
			networkInterfaces = append(networkInterfaces, networkInterface)
		}
	}

	return networkInterfaces
}

package compute

import (
	"encoding/base64"

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
			Metadata:          resource.Metadata,
			CustomData:        adaptCustomData(resource),
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
			Metadata:          resource.Metadata,
			CustomData:        adaptCustomData(resource),
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

// adaptCustomData decodes osProfile.customData, which ARM requires to be base64
// encoded. A value that isn't valid base64 is kept as written, as in the
// Terraform adapter.
func adaptCustomData(resource azure.Resource) iacTypes.StringValue {
	customData := resource.Properties.GetMapValue("osProfile").
		GetMapValue("customData").AsStringValue("", resource.Metadata)
	decoded, err := base64.StdEncoding.DecodeString(customData.Value())
	if err != nil {
		return customData
	}
	return iacTypes.String(string(decoded), customData.GetMetadata())
}

func extractNetworkInterfaces(_ azure.Value, _ iacTypes.Metadata) []network.NetworkInterface {
	return nil
}

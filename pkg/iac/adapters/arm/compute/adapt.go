package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/compute"
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

func adaptManagedDisks(deployment azure.Deployment) (managedDisks []compute.ManagedDisk) {

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
	return compute.WindowsVirtualMachine{
		Metadata: resource.Metadata,
		VirtualMachine: compute.VirtualMachine{
			Metadata: resource.Metadata,
			CustomData: resource.Properties.GetMapValue("osProfile").
				GetMapValue("customData").AsStringValue("", resource.Metadata),
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
	return compute.LinuxVirtualMachine{
		Metadata: resource.Metadata,
		VirtualMachine: compute.VirtualMachine{
			Metadata: resource.Metadata,
			CustomData: resource.Properties.GetMapValue("osProfile").
				GetMapValue("customData").AsStringValue("", resource.Metadata),
		},
		OSProfileLinuxConfig: compute.OSProfileLinuxConfig{
			Metadata: resource.Metadata,
			DisablePasswordAuthentication: resource.Properties.GetMapValue("osProfile").
				GetMapValue("linuxConfiguration").
				GetMapValue("disablePasswordAuthentication").AsBoolValue(false, resource.Metadata),
		},
	}

}

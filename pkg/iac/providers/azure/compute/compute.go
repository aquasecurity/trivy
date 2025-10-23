package compute

import (
	"github.com/aquasecurity/trivy/pkg/iac/providers/azure/network"
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	Metadata          iacTypes.Metadata
	CustomData        iacTypes.StringValue // NOT base64 encoded
	NetworkInterfaces []NetworkInterface
}

type NetworkInterface struct {
	Metadata        iacTypes.Metadata
	SubnetID        iacTypes.StringValue
	SecurityGroups  []network.SecurityGroup
	HasPublicIP     iacTypes.BoolValue
	PublicIPAddress iacTypes.StringValue
}

type LinuxVirtualMachine struct {
	Metadata iacTypes.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	Metadata iacTypes.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	Metadata                      iacTypes.Metadata
	DisablePasswordAuthentication iacTypes.BoolValue
}

type ManagedDisk struct {
	Metadata   iacTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	Metadata   iacTypes.Metadata
	CustomData iacTypes.StringValue // NOT base64 encoded
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

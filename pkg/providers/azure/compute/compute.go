package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	Metadata   defsecTypes.MisconfigMetadata
	CustomData defsecTypes.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	Metadata defsecTypes.MisconfigMetadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	Metadata defsecTypes.MisconfigMetadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	Metadata                      defsecTypes.MisconfigMetadata
	DisablePasswordAuthentication defsecTypes.BoolValue
}

type ManagedDisk struct {
	Metadata   defsecTypes.MisconfigMetadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

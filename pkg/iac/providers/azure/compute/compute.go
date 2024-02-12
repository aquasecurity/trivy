package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Compute struct {
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	Metadata   defsecTypes.Metadata
	CustomData defsecTypes.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	Metadata defsecTypes.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	Metadata defsecTypes.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	Metadata                      defsecTypes.Metadata
	DisablePasswordAuthentication defsecTypes.BoolValue
}

type ManagedDisk struct {
	Metadata   defsecTypes.Metadata
	Encryption Encryption
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

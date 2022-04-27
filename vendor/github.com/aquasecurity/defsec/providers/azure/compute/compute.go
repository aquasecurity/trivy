package compute

import "github.com/aquasecurity/defsec/parsers/types"

type Compute struct {
	types.Metadata
	Name                   types.StringValue
	Region                 types.StringValue
	LinuxVirtualMachines   []LinuxVirtualMachine
	WindowsVirtualMachines []WindowsVirtualMachine
	ManagedDisks           []ManagedDisk
}

type VirtualMachine struct {
	types.Metadata
	CustomData types.StringValue // NOT base64 encoded
}

type LinuxVirtualMachine struct {
	types.Metadata
	VirtualMachine
	OSProfileLinuxConfig OSProfileLinuxConfig
}

type WindowsVirtualMachine struct {
	types.Metadata
	VirtualMachine
}

type OSProfileLinuxConfig struct {
	types.Metadata
	DisablePasswordAuthentication types.BoolValue
}

type ManagedDisk struct {
	types.Metadata
	Encryption Encryption
}

type Encryption struct {
	types.Metadata
	Enabled types.BoolValue
}

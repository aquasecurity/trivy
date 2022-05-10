package compute

import "github.com/aquasecurity/defsec/parsers/types"

type Instance struct {
	types.Metadata
	Name                        types.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                types.BoolValue
	OSLoginEnabled              types.BoolValue
	EnableProjectSSHKeyBlocking types.BoolValue
	EnableSerialPort            types.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	types.Metadata
	Email  types.StringValue
	Scopes []types.StringValue
}

type NetworkInterface struct {
	types.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP types.BoolValue
	NATIP       types.StringValue
}

type ShieldedVMConfig struct {
	types.Metadata
	SecureBootEnabled          types.BoolValue
	IntegrityMonitoringEnabled types.BoolValue
	VTPMEnabled                types.BoolValue
}

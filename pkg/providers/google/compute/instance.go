package compute

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Instance struct {
	Metadata                    defsecTypes.MisconfigMetadata
	Name                        defsecTypes.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                defsecTypes.BoolValue
	OSLoginEnabled              defsecTypes.BoolValue
	EnableProjectSSHKeyBlocking defsecTypes.BoolValue
	EnableSerialPort            defsecTypes.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	Metadata  defsecTypes.MisconfigMetadata
	Email     defsecTypes.StringValue
	IsDefault defsecTypes.BoolValue
	Scopes    []defsecTypes.StringValue
}

type NetworkInterface struct {
	Metadata    defsecTypes.MisconfigMetadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP defsecTypes.BoolValue
	NATIP       defsecTypes.StringValue
}

type ShieldedVMConfig struct {
	Metadata                   defsecTypes.MisconfigMetadata
	SecureBootEnabled          defsecTypes.BoolValue
	IntegrityMonitoringEnabled defsecTypes.BoolValue
	VTPMEnabled                defsecTypes.BoolValue
}

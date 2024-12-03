package compute

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Instance struct {
	Metadata                    iacTypes.Metadata
	Name                        iacTypes.StringValue
	NetworkInterfaces           []NetworkInterface
	ShieldedVM                  ShieldedVMConfig
	ServiceAccount              ServiceAccount
	CanIPForward                iacTypes.BoolValue
	OSLoginEnabled              iacTypes.BoolValue
	EnableProjectSSHKeyBlocking iacTypes.BoolValue
	EnableSerialPort            iacTypes.BoolValue
	BootDisks                   []Disk
	AttachedDisks               []Disk
}

type ServiceAccount struct {
	Metadata  iacTypes.Metadata
	Email     iacTypes.StringValue
	IsDefault iacTypes.BoolValue
	Scopes    []iacTypes.StringValue
}

type NetworkInterface struct {
	Metadata    iacTypes.Metadata
	Network     *Network
	SubNetwork  *SubNetwork
	HasPublicIP iacTypes.BoolValue
	NATIP       iacTypes.StringValue
}

type ShieldedVMConfig struct {
	Metadata                   iacTypes.Metadata
	SecureBootEnabled          iacTypes.BoolValue
	IntegrityMonitoringEnabled iacTypes.BoolValue
	VTPMEnabled                iacTypes.BoolValue
}

package gke

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata                 defsecTypes.MisconfigMetadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           defsecTypes.StringValue
	MonitoringService        defsecTypes.StringValue
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      defsecTypes.BoolValue
	EnableLegacyABAC         defsecTypes.BoolValue
	ResourceLabels           defsecTypes.MapValue
	RemoveDefaultNodePool    defsecTypes.BoolValue
	EnableAutpilot           defsecTypes.BoolValue
	DatapathProvider         defsecTypes.StringValue
}

type NodeConfig struct {
	Metadata               defsecTypes.MisconfigMetadata
	ImageType              defsecTypes.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         defsecTypes.StringValue
	EnableLegacyEndpoints  defsecTypes.BoolValue
}

type WorkloadMetadataConfig struct {
	Metadata     defsecTypes.MisconfigMetadata
	NodeMetadata defsecTypes.StringValue
}

type MasterAuth struct {
	Metadata          defsecTypes.MisconfigMetadata
	ClientCertificate ClientCertificate
	Username          defsecTypes.StringValue
	Password          defsecTypes.StringValue
}

type ClientCertificate struct {
	Metadata         defsecTypes.MisconfigMetadata
	IssueCertificate defsecTypes.BoolValue
}

type PrivateCluster struct {
	Metadata           defsecTypes.MisconfigMetadata
	EnablePrivateNodes defsecTypes.BoolValue
}

type NetworkPolicy struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type MasterAuthorizedNetworks struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	CIDRs    []defsecTypes.StringValue
}

type IPAllocationPolicy struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type NodePool struct {
	Metadata   defsecTypes.MisconfigMetadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	Metadata          defsecTypes.MisconfigMetadata
	EnableAutoRepair  defsecTypes.BoolValue
	EnableAutoUpgrade defsecTypes.BoolValue
}

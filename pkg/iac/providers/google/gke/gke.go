package gke

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata                 defsecTypes.Metadata
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
	Metadata               defsecTypes.Metadata
	ImageType              defsecTypes.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         defsecTypes.StringValue
	EnableLegacyEndpoints  defsecTypes.BoolValue
}

type WorkloadMetadataConfig struct {
	Metadata     defsecTypes.Metadata
	NodeMetadata defsecTypes.StringValue
}

type MasterAuth struct {
	Metadata          defsecTypes.Metadata
	ClientCertificate ClientCertificate
	Username          defsecTypes.StringValue
	Password          defsecTypes.StringValue
}

type ClientCertificate struct {
	Metadata         defsecTypes.Metadata
	IssueCertificate defsecTypes.BoolValue
}

type PrivateCluster struct {
	Metadata           defsecTypes.Metadata
	EnablePrivateNodes defsecTypes.BoolValue
}

type NetworkPolicy struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type MasterAuthorizedNetworks struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	CIDRs    []defsecTypes.StringValue
}

type IPAllocationPolicy struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type NodePool struct {
	Metadata   defsecTypes.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	Metadata          defsecTypes.Metadata
	EnableAutoRepair  defsecTypes.BoolValue
	EnableAutoUpgrade defsecTypes.BoolValue
}

package gke

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type GKE struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata                 iacTypes.Metadata
	NodePools                []NodePool
	IPAllocationPolicy       IPAllocationPolicy
	MasterAuthorizedNetworks MasterAuthorizedNetworks
	NetworkPolicy            NetworkPolicy
	PrivateCluster           PrivateCluster
	LoggingService           iacTypes.StringValue
	MonitoringService        iacTypes.StringValue
	MasterAuth               MasterAuth
	NodeConfig               NodeConfig
	EnableShieldedNodes      iacTypes.BoolValue
	EnableLegacyABAC         iacTypes.BoolValue
	ResourceLabels           iacTypes.MapValue
	RemoveDefaultNodePool    iacTypes.BoolValue
	EnableAutpilot           iacTypes.BoolValue
	DatapathProvider         iacTypes.StringValue
}

type NodeConfig struct {
	Metadata               iacTypes.Metadata
	ImageType              iacTypes.StringValue
	WorkloadMetadataConfig WorkloadMetadataConfig
	ServiceAccount         iacTypes.StringValue
	EnableLegacyEndpoints  iacTypes.BoolValue
}

type WorkloadMetadataConfig struct {
	Metadata     iacTypes.Metadata
	NodeMetadata iacTypes.StringValue
}

type MasterAuth struct {
	Metadata          iacTypes.Metadata
	ClientCertificate ClientCertificate
	Username          iacTypes.StringValue
	Password          iacTypes.StringValue
}

type ClientCertificate struct {
	Metadata         iacTypes.Metadata
	IssueCertificate iacTypes.BoolValue
}

type PrivateCluster struct {
	Metadata           iacTypes.Metadata
	EnablePrivateNodes iacTypes.BoolValue
}

type NetworkPolicy struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type MasterAuthorizedNetworks struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	CIDRs    []iacTypes.StringValue
}

type IPAllocationPolicy struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type NodePool struct {
	Metadata   iacTypes.Metadata
	Management Management
	NodeConfig NodeConfig
}

type Management struct {
	Metadata          iacTypes.Metadata
	EnableAutoRepair  iacTypes.BoolValue
	EnableAutoUpgrade iacTypes.BoolValue
}

package container

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	Metadata                    iacTypes.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        iacTypes.BoolValue
	APIServerAuthorizedIPRanges []iacTypes.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type AddonProfile struct {
	Metadata iacTypes.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
}

type NetworkProfile struct {
	Metadata      iacTypes.Metadata
	NetworkPolicy iacTypes.StringValue // "", "calico", "azure"
}

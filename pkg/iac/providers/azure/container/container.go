package container

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	Metadata                    defsecTypes.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        defsecTypes.BoolValue
	APIServerAuthorizedIPRanges []defsecTypes.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type AddonProfile struct {
	Metadata defsecTypes.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
}

type NetworkProfile struct {
	Metadata      defsecTypes.Metadata
	NetworkPolicy defsecTypes.StringValue // "", "calico", "azure"
}

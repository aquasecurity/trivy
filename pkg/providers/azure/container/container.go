package container

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Container struct {
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	Metadata                    defsecTypes.MisconfigMetadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        defsecTypes.BoolValue
	APIServerAuthorizedIPRanges []defsecTypes.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type AddonProfile struct {
	Metadata defsecTypes.MisconfigMetadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
}

type NetworkProfile struct {
	Metadata      defsecTypes.MisconfigMetadata
	NetworkPolicy defsecTypes.StringValue // "", "calico", "azure"
}

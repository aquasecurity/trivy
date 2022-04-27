package container

import "github.com/aquasecurity/defsec/parsers/types"

type Container struct {
	types.Metadata
	KubernetesClusters []KubernetesCluster
}

type KubernetesCluster struct {
	types.Metadata
	NetworkProfile              NetworkProfile
	EnablePrivateCluster        types.BoolValue
	APIServerAuthorizedIPRanges []types.StringValue
	AddonProfile                AddonProfile
	RoleBasedAccessControl      RoleBasedAccessControl
}

type RoleBasedAccessControl struct {
	types.Metadata
	Enabled types.BoolValue
}

type AddonProfile struct {
	types.Metadata
	OMSAgent OMSAgent
}

type OMSAgent struct {
	types.Metadata
	Enabled types.BoolValue
}

type NetworkProfile struct {
	types.Metadata
	NetworkPolicy types.StringValue // "", "calico", "azure"
}

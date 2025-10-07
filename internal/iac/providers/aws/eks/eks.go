package eks

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            iacTypes.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled iacTypes.BoolValue
	PublicAccessCIDRs   []iacTypes.StringValue
}

type Logging struct {
	Metadata          iacTypes.Metadata
	API               iacTypes.BoolValue
	Audit             iacTypes.BoolValue
	Authenticator     iacTypes.BoolValue
	ControllerManager iacTypes.BoolValue
	Scheduler         iacTypes.BoolValue
}

type Encryption struct {
	Metadata iacTypes.Metadata
	Secrets  iacTypes.BoolValue
	KMSKeyID iacTypes.StringValue
}

package eks

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            defsecTypes.Metadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled defsecTypes.BoolValue
	PublicAccessCIDRs   []defsecTypes.StringValue
}

type Logging struct {
	Metadata          defsecTypes.Metadata
	API               defsecTypes.BoolValue
	Audit             defsecTypes.BoolValue
	Authenticator     defsecTypes.BoolValue
	ControllerManager defsecTypes.BoolValue
	Scheduler         defsecTypes.BoolValue
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Secrets  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

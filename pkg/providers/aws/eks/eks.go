package eks

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type EKS struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata            defsecTypes.MisconfigMetadata
	Logging             Logging
	Encryption          Encryption
	PublicAccessEnabled defsecTypes.BoolValue
	PublicAccessCIDRs   []defsecTypes.StringValue
}

type Logging struct {
	Metadata          defsecTypes.MisconfigMetadata
	API               defsecTypes.BoolValue
	Audit             defsecTypes.BoolValue
	Authenticator     defsecTypes.BoolValue
	ControllerManager defsecTypes.BoolValue
	Scheduler         defsecTypes.BoolValue
}

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Secrets  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

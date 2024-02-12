package neptune

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata         defsecTypes.Metadata
	Logging          Logging
	StorageEncrypted defsecTypes.BoolValue
	KMSKeyID         defsecTypes.StringValue
}

type Logging struct {
	Metadata defsecTypes.Metadata
	Audit    defsecTypes.BoolValue
}

package neptune

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata         defsecTypes.MisconfigMetadata
	Logging          Logging
	StorageEncrypted defsecTypes.BoolValue
	KMSKeyID         defsecTypes.StringValue
}

type Logging struct {
	Metadata defsecTypes.MisconfigMetadata
	Audit    defsecTypes.BoolValue
}

package neptune

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	Metadata         iacTypes.Metadata
	Logging          Logging
	StorageEncrypted iacTypes.BoolValue
	KMSKeyID         iacTypes.StringValue
}

type Logging struct {
	Metadata iacTypes.Metadata
	Audit    iacTypes.BoolValue
}

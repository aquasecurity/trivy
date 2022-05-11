package neptune

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type Neptune struct {
	Clusters []Cluster
}

type Cluster struct {
	types.Metadata
	Logging          Logging
	StorageEncrypted types.BoolValue
	KMSKeyID         types.StringValue
}

type Logging struct {
	types.Metadata
	Audit types.BoolValue
}

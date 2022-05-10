package neptune

import "github.com/aquasecurity/defsec/parsers/types"

type Neptune struct {
	types.Metadata
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

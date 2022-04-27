package documentdb

import "github.com/aquasecurity/defsec/parsers/types"

type DocumentDB struct {
	types.Metadata
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	types.Metadata
	Identifier        types.StringValue
	EnabledLogExports []types.StringValue
	Instances         []Instance
	StorageEncrypted  types.BoolValue
	KMSKeyID          types.StringValue
}

type Instance struct {
	types.Metadata
	KMSKeyID types.StringValue
}

package documentdb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	Metadata              defsecTypes.MisconfigMetadata
	Identifier            defsecTypes.StringValue
	EnabledLogExports     []defsecTypes.StringValue
	BackupRetentionPeriod defsecTypes.IntValue
	Instances             []Instance
	StorageEncrypted      defsecTypes.BoolValue
	KMSKeyID              defsecTypes.StringValue
}

type Instance struct {
	Metadata defsecTypes.MisconfigMetadata
	KMSKeyID defsecTypes.StringValue
}

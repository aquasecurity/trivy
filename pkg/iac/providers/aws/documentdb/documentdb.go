package documentdb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DocumentDB struct {
	Clusters []Cluster
}

const (
	LogExportAudit    = "audit"
	LogExportProfiler = "profiler"
)

type Cluster struct {
	Metadata              defsecTypes.Metadata
	Identifier            defsecTypes.StringValue
	EnabledLogExports     []defsecTypes.StringValue
	BackupRetentionPeriod defsecTypes.IntValue
	Instances             []Instance
	StorageEncrypted      defsecTypes.BoolValue
	KMSKeyID              defsecTypes.StringValue
}

type Instance struct {
	Metadata defsecTypes.Metadata
	KMSKeyID defsecTypes.StringValue
}

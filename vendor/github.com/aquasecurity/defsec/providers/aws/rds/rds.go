package rds

import "github.com/aquasecurity/defsec/parsers/types"

type RDS struct {
	types.Metadata
	Instances []Instance
	Clusters  []Cluster
	Classic   Classic
}

type Cluster struct {
	types.Metadata
	BackupRetentionPeriodDays types.IntValue
	ReplicationSourceARN      types.StringValue
	PerformanceInsights       PerformanceInsights
	Instances                 []ClusterInstance
	Encryption                Encryption
}

type Encryption struct {
	types.Metadata
	EncryptStorage types.BoolValue
	KMSKeyID       types.StringValue
}

type Instance struct {
	types.Metadata
	BackupRetentionPeriodDays types.IntValue
	ReplicationSourceARN      types.StringValue
	PerformanceInsights       PerformanceInsights
	Encryption                Encryption
	PublicAccess              types.BoolValue
}

type ClusterInstance struct {
	types.Metadata
	Instance
	ClusterIdentifier types.StringValue
}

type PerformanceInsights struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

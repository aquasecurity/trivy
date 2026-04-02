package elasticache

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	Metadata               iacTypes.Metadata
	Engine                 iacTypes.StringValue
	NodeType               iacTypes.StringValue
	SnapshotRetentionLimit iacTypes.IntValue // days
}

type ReplicationGroup struct {
	Metadata                 iacTypes.Metadata
	TransitEncryptionEnabled iacTypes.BoolValue
	AtRestEncryptionEnabled  iacTypes.BoolValue
}

type SecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
}

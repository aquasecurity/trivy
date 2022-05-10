package elasticache

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	types.Metadata
	Engine                 types.StringValue
	NodeType               types.StringValue
	SnapshotRetentionLimit types.IntValue // days
}

type ReplicationGroup struct {
	types.Metadata
	TransitEncryptionEnabled types.BoolValue
	AtRestEncryptionEnabled  types.BoolValue
}

type SecurityGroup struct {
	types.Metadata
	Description types.StringValue
}

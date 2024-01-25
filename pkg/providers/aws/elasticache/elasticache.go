package elasticache

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type ElastiCache struct {
	Clusters          []Cluster
	ReplicationGroups []ReplicationGroup
	SecurityGroups    []SecurityGroup
}

type Cluster struct {
	Metadata               defsecTypes.MisconfigMetadata
	Engine                 defsecTypes.StringValue
	NodeType               defsecTypes.StringValue
	SnapshotRetentionLimit defsecTypes.IntValue // days
}

type ReplicationGroup struct {
	Metadata                 defsecTypes.MisconfigMetadata
	TransitEncryptionEnabled defsecTypes.BoolValue
	AtRestEncryptionEnabled  defsecTypes.BoolValue
}

type SecurityGroup struct {
	Metadata    defsecTypes.MisconfigMetadata
	Description defsecTypes.StringValue
}

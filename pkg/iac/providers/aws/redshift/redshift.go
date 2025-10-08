package redshift

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Redshift struct {
	Clusters          []Cluster
	ReservedNodes     []ReservedNode
	ClusterParameters []ClusterParameter
	SecurityGroups    []SecurityGroup
}

type SecurityGroup struct {
	Metadata    iacTypes.Metadata
	Description iacTypes.StringValue
}

type ReservedNode struct {
	Metadata iacTypes.Metadata
	NodeType iacTypes.StringValue
}

type ClusterParameter struct {
	Metadata       iacTypes.Metadata
	ParameterName  iacTypes.StringValue
	ParameterValue iacTypes.StringValue
}

type Cluster struct {
	Metadata                         iacTypes.Metadata
	ClusterIdentifier                iacTypes.StringValue
	NodeType                         iacTypes.StringValue
	VpcId                            iacTypes.StringValue
	NumberOfNodes                    iacTypes.IntValue
	PubliclyAccessible               iacTypes.BoolValue
	AllowVersionUpgrade              iacTypes.BoolValue
	MasterUsername                   iacTypes.StringValue
	AutomatedSnapshotRetentionPeriod iacTypes.IntValue
	LoggingEnabled                   iacTypes.BoolValue
	EndPoint                         EndPoint
	Encryption                       Encryption
	SubnetGroupName                  iacTypes.StringValue
}

type EndPoint struct {
	Metadata iacTypes.Metadata
	Port     iacTypes.IntValue
}

type Encryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	KMSKeyID iacTypes.StringValue
}

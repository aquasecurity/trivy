package redshift

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type Redshift struct {
	Clusters          []Cluster
	ReservedNodes     []ReservedNode
	ClusterParameters []ClusterParameter
	SecurityGroups    []SecurityGroup
}

type SecurityGroup struct {
	Metadata    defsecTypes.MisconfigMetadata
	Description defsecTypes.StringValue
}

type ReservedNode struct {
	Metadata defsecTypes.MisconfigMetadata
	NodeType defsecTypes.StringValue
}

type ClusterParameter struct {
	Metadata       defsecTypes.MisconfigMetadata
	ParameterName  defsecTypes.StringValue
	ParameterValue defsecTypes.StringValue
}

type Cluster struct {
	Metadata                         defsecTypes.MisconfigMetadata
	ClusterIdentifier                defsecTypes.StringValue
	NodeType                         defsecTypes.StringValue
	VpcId                            defsecTypes.StringValue
	NumberOfNodes                    defsecTypes.IntValue
	PubliclyAccessible               defsecTypes.BoolValue
	AllowVersionUpgrade              defsecTypes.BoolValue
	MasterUsername                   defsecTypes.StringValue
	AutomatedSnapshotRetentionPeriod defsecTypes.IntValue
	LoggingEnabled                   defsecTypes.BoolValue
	EndPoint                         EndPoint
	Encryption                       Encryption
	SubnetGroupName                  defsecTypes.StringValue
}

type EndPoint struct {
	Metadata defsecTypes.MisconfigMetadata
	Port     defsecTypes.IntValue
}

type Encryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

package redshift

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type Redshift struct {
	Clusters          []Cluster
	ReservedNodes     []ReservedNode
	ClusterParameters []ClusterParameter
	SecurityGroups    []SecurityGroup
}

type SecurityGroup struct {
	Metadata    defsecTypes.Metadata
	Description defsecTypes.StringValue
}

type ReservedNode struct {
	Metadata defsecTypes.Metadata
	NodeType defsecTypes.StringValue
}

type ClusterParameter struct {
	Metadata       defsecTypes.Metadata
	ParameterName  defsecTypes.StringValue
	ParameterValue defsecTypes.StringValue
}

type Cluster struct {
	Metadata                         defsecTypes.Metadata
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
	Metadata defsecTypes.Metadata
	Port     defsecTypes.IntValue
}

type Encryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

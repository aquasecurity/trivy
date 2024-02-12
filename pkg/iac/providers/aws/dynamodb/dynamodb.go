package dynamodb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
}

type DAXCluster struct {
	Metadata             defsecTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type Table struct {
	Metadata             defsecTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type ServerSideEncryption struct {
	Metadata defsecTypes.Metadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

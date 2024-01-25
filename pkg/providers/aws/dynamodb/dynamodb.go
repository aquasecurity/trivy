package dynamodb

import (
	defsecTypes "github.com/aquasecurity/trivy/pkg/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
}

type DAXCluster struct {
	Metadata             defsecTypes.MisconfigMetadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type Table struct {
	Metadata             defsecTypes.MisconfigMetadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  defsecTypes.BoolValue
}

type ServerSideEncryption struct {
	Metadata defsecTypes.MisconfigMetadata
	Enabled  defsecTypes.BoolValue
	KMSKeyID defsecTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

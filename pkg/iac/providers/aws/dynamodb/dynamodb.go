package dynamodb

import (
	iacTypes "github.com/aquasecurity/trivy/pkg/iac/types"
)

type DynamoDB struct {
	DAXClusters []DAXCluster
	Tables      []Table
}

type DAXCluster struct {
	Metadata             iacTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  iacTypes.BoolValue
}

type Table struct {
	Metadata             iacTypes.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  iacTypes.BoolValue
}

type ServerSideEncryption struct {
	Metadata iacTypes.Metadata
	Enabled  iacTypes.BoolValue
	KMSKeyID iacTypes.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

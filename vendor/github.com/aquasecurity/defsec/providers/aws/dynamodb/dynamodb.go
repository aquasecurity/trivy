package dynamodb

import "github.com/aquasecurity/defsec/parsers/types"

type DynamoDB struct {
	types.Metadata
	DAXClusters []DAXCluster
}

type DAXCluster struct {
	types.Metadata
	ServerSideEncryption ServerSideEncryption
	PointInTimeRecovery  types.BoolValue
}

type ServerSideEncryption struct {
	types.Metadata
	Enabled  types.BoolValue
	KMSKeyID types.StringValue
}

const DefaultKMSKeyID = "alias/aws/dynamodb"

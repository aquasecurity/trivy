package dynamodb

import (
	"github.com/aquasecurity/defsec/internal/types"
)

type DynamoDB struct {
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

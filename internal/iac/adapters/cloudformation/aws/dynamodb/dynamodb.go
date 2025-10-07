package dynamodb

import (
	"github.com/aquasecurity/trivy/internal/iac/providers/aws/dynamodb"
	"github.com/aquasecurity/trivy/internal/iac/scanners/cloudformation/parser"
)

// Adapt adapts a dynamodb instance
func Adapt(cfFile parser.FileContext) dynamodb.DynamoDB {
	return dynamodb.DynamoDB{
		DAXClusters: getClusters(cfFile),
		Tables:      getTables(cfFile),
	}
}
